import argparse
import io
import socket

import pytest
import samples as S
from conftest import CF6, G6, FakeNet
from rich.console import Console

from wtfnet import checks, cli, parsers
from wtfnet import platform_cmds as pc
from wtfnet.checks import STEPS, STEPS6, has_ipv6
from wtfnet.models import FAIL, OK, SKIP, WARN
from wtfnet.verdict import compute_verdict

DEAD6 = S.PING6_LINUX_DEAD
TIMEOUT = S.NSLOOKUP_TIMEOUT


def run_all(net, **ctx_kw):
    """Run the battery exactly like the CLI does: IPv6 steps join once we know there's IPv6."""
    ctx = net.context(**ctx_kw)
    steps, results, i = list(STEPS), [], 0
    while i < len(steps):
        results.append(steps[i].fn(ctx))
        if steps[i].key == "interfaces" and has_ipv6(ctx):
            steps.extend(STEPS6)
        i += 1
    return {r.key: r for r in results}, compute_verdict(results, ctx.target), ctx


# ------------------------------------------------------------- parsers
def test_interfaces6_linux_drops_loopback_and_flags_scope():
    got = parsers.parse_interfaces6(S.IFACES_IP_V6, "ip")
    assert [(i.name, i.ip) for i in got] == [
        ("wlan0", "2607:f8b0:4005:80a::2003"), ("wlan0", "fe80::1c2b:3d4e:5f60:7182")]
    assert got[0].is_global and not got[0].is_link_local
    assert got[1].is_link_local and not got[1].is_global


def test_interfaces6_macos_strips_zone_id():
    got = parsers.parse_interfaces6(S.IFACES_IFCONFIG_V6, "ifconfig")
    assert [i.ip for i in got if i.is_global] == ["2607:f8b0:4005:80a::2003"]
    assert all("%" not in i.ip for i in got)  # fe80::1%en0 -> fe80::1
    assert {i.name for i in got} == {"en0"}  # loopback (lo0) is dropped


def test_interfaces6_windows_includes_temporary_and_link_local():
    got = parsers.parse_interfaces6(S.IFACES_IPCONFIG_V6, "ipconfig")
    assert len(got) == 3 and sum(i.is_global for i in got) == 2
    assert got[2].ip == "fe80::1c2b:3d4e:5f60:7182"  # %12 zone removed


def test_private_ula_and_link_local_are_not_global():
    got = parsers.parse_interfaces6(S.IFACES_IP_V6_LOCAL_ONLY, "ip")
    assert len(got) == 2 and not any(i.is_global for i in got)


def test_default_route6_all_formats_get_a_scope():
    assert parsers.parse_default_route6(S.GATEWAY6_LINUX) == "fe80::1%wlan0"
    assert parsers.parse_default_route6(S.GATEWAY6_MAC) == "fe80::1%en0"
    assert parsers.parse_default_route6(S.GATEWAY6_WIN) == "fe80::1%12"
    assert parsers.parse_default_route6(S.GATEWAY6_NETSTAT) == "fe80::1%wlan0"


def test_v4_and_v6_gateway_parsers_dont_mistake_each_other():
    assert parsers.parse_default_route6(S.GATEWAY_LINUX) is None
    assert parsers.parse_default_route6(S.GATEWAY_MAC) is None
    assert parsers.parse_default_route6("") is None
    assert parsers.parse_gateway(S.GATEWAY6_LINUX) is None
    assert parsers.parse_gateway(S.GATEWAY6_MAC) is None


def test_ping6_linux_and_macos_hlim():
    assert parsers.parse_ping(S.PING6_LINUX_OK, "linux").avg_ms == 14.3
    mac = parsers.parse_ping(S.PING6_MAC_OK, "darwin")
    assert (mac.sent, mac.received, mac.avg_ms) == (4, 4, 14.3)


def test_ping6_windows_has_no_ttl_but_still_counts_replies():
    s = parsers.parse_ping(S.PING6_WIN_OK, "windows")
    assert (s.sent, s.received, s.avg_ms) == (4, 4, 10.0)


def test_ping6_windows_unreachable_and_dead():
    assert parsers.parse_ping(S.PING6_WIN_UNREACHABLE, "windows").received == 0
    assert parsers.parse_ping(DEAD6, "linux").loss_pct == 100


def test_nslookup_aaaa_unix_and_windows():
    assert parsers.parse_nslookup(S.NSLOOKUP_AAAA_OK, 6).answers == ["2606:2800:21f:cb07:6820:80da:af6b:8b2c"]
    assert len(parsers.parse_nslookup(S.NSLOOKUP_AAAA_WIN, 6).answers) == 2


def test_nslookup_aaaa_with_no_record_is_not_a_failure_code():
    r = parsers.parse_nslookup(S.NSLOOKUP_AAAA_NONE, 6)
    assert not r.ok and r.error == "noanswer"


def test_nslookup_family_filters_record_types():
    assert not parsers.parse_nslookup(S.NSLOOKUP_AAAA_OK, 4).ok
    assert not parsers.parse_nslookup(S.NSLOOKUP_UNIX_OK, 6).ok


def test_traceroute6_reached_unix_and_windows():
    unix = parsers.parse_traceroute(S.TRACE6_UNIX_REACHED, "example.com")
    assert unix.reached and unix.hops[0].ip == "fe80::1" and unix.hops[2].ip is None
    assert parsers.parse_traceroute(S.TRACE6_WIN_REACHED, "example.com").reached


def test_traceroute6_compares_addresses_not_spellings():
    assert parsers.parse_traceroute(S.TRACE6_UNIX_EXPANDED_HEADER, "example.com").reached


def test_traceroute6_stalled():
    t = parsers.parse_traceroute(S.TRACE6_UNIX_STALLED, "example.com")
    assert not t.reached and len(t.responding) == 1


def test_ip_family():
    assert parsers.ip_family("1.2.3.4") == 4
    assert parsers.ip_family("::1") == 6
    assert parsers.ip_family("example.com") is None


# ------------------------------------------------------------ commands
def test_ipv6_ping_commands_per_os():
    assert pc.ping_cmd("h", "linux", family=6)[:3] == ["ping", "-6", "-c"]
    assert pc.ping_cmd("h", "darwin", family=6)[0] == "ping6"
    assert pc.ping_cmd("h", "windows", family=6)[:3] == ["ping", "-6", "-n"]
    assert pc.ping_cmd("h", "linux")[1] == "-c"  # IPv4 unchanged


def test_ipv6_traceroute_commands_per_os():
    assert pc.traceroute_cmd("h", "linux", family=6)[:2] == ["traceroute", "-6"]
    assert pc.traceroute_cmd("h", "darwin", family=6)[0] == "traceroute6"
    assert pc.traceroute_cmd("h", "windows", family=6)[:2] == ["tracert", "-6"]


def test_ipv6_gateway_and_dns_commands():
    assert pc.gateway6_cmd("linux", lambda n: "/bin/ip") == ["ip", "-6", "route", "show", "default"]
    assert pc.gateway6_cmd("linux", lambda n: None)[:2] == ["netstat", "-rn"]
    assert pc.gateway6_cmd("darwin")[-2:] == ["-inet6", "default"]
    assert pc.gateway6_cmd("windows") == ["route", "print", "-6"]
    assert "-type=AAAA" in pc.nslookup_cmd("a.com", "1.1.1.1", "AAAA")
    assert pc.nslookup_cmd("a.com", "1.1.1.1", "AAAA")[-2:] == ["a.com", "1.1.1.1"]


def test_linux_interfaces_command_lists_both_families():
    assert pc.interfaces_cmd("linux", lambda n: "/bin/ip") == ["ip", "-o", "addr", "show"]


# ----------------------------------------------------------- scenarios
def test_healthy_dual_stack_runs_eleven_steps_and_all_pass(healthy6):
    steps, v = run_all(healthy6)[:2]
    assert len(steps) == 11 and all(s.status == OK for s in steps.values())
    assert (v.layer, v.status) == ("none", OK)
    assert any("IPv6 is reachable" in e for e in v.evidence)


def test_ipv6_steps_show_exact_commands(healthy6):
    steps = run_all(healthy6)[0]
    assert [e.display for e in steps["gateway6"].execs][0] == "ip -6 route show default"
    assert steps["gateway6"].execs[1].display.startswith("ping -6 -c 4")
    assert "fe80::1%wlan0" in steps["gateway6"].execs[1].display
    assert "-type=AAAA" in steps["dns6"].execs[0].display
    assert steps["traceroute6"].execs[0].display.startswith("traceroute -6")
    assert "AF_INET6" in steps["ports6"].execs[0].display


def test_no_global_ipv6_means_no_ipv6_steps_and_a_friendly_note(healthy):
    steps = run_all(healthy)[0]
    assert len(steps) == 6 and "gateway6" not in steps
    assert "IPv4-only" in steps["interfaces"].explanation


def test_link_local_and_private_ula_dont_trigger_ipv6_tests():
    net = FakeNet(ifaces=S.IFACES_IP_V6_LOCAL_ONLY)
    assert len(run_all(net)[0]) == 6


def test_no_ipv6_flag_disables_the_steps_even_with_an_address(healthy6):
    steps = run_all(healthy6, ipv6=False)[0]
    assert len(steps) == 6 and "IPv6" not in steps["interfaces"].explanation


def test_ipv6_broken_while_ipv4_fine_is_a_warning_not_a_blame_on_the_isp():
    net = FakeNet(v6=True, gw6_ping=DEAD6, cf6_ping=DEAD6, g6_ping=DEAD6,
                  dns6={None: TIMEOUT, CF6: TIMEOUT, G6: TIMEOUT},
                  ports6={80: "filtered", 443: "filtered"})
    steps, v, _ = run_all(net)
    assert steps["internet6"].status == FAIL
    assert steps["traceroute6"].status == SKIP  # not worth waiting for
    assert not any("-6" in c for c in net.calls if c[0] == "traceroute")
    assert (v.layer, v.status) == ("ipv6", WARN)


def test_missing_ipv6_default_route_explains_router_advertisements():
    steps = run_all(FakeNet(v6=True, gateway6=""))[0]
    assert steps["gateway6"].status == FAIL
    assert "Router Advertisements" in steps["gateway6"].explanation


def test_target_reachable_over_v4_but_not_v6_is_an_ipv6_warning():
    net = FakeNet(v6=True, ports6={80: "filtered", 443: "filtered"})
    _, v, _ = run_all(net)
    assert (v.layer, v.status) == ("ipv6", WARN)
    assert any("reachable over IPv4 but not IPv6" in e for e in v.evidence)


def test_target_with_no_aaaa_record_is_skipped_not_blamed():
    net = FakeNet(v6=True, ports6={80: "noaddr", 443: "noaddr"})
    steps, v, _ = run_all(net)
    assert steps["ports6"].status == SKIP and "AAAA" in steps["ports6"].explanation
    assert (v.layer, v.status) == ("none", OK)


def test_dns_name_without_aaaa_is_skipped_not_failed():
    none = {None: S.NSLOOKUP_AAAA_NONE, CF6: S.NSLOOKUP_AAAA_NONE, G6: S.NSLOOKUP_AAAA_NONE}
    steps, v, _ = run_all(FakeNet(v6=True, dns6=none))
    assert steps["dns6"].status == SKIP and "AAAA" in steps["dns6"].explanation
    assert v.status == OK


def test_ipv4_literal_target_skips_ipv6_target_steps():
    steps = run_all(FakeNet(v6=True), target="93.184.216.34")[0]
    assert steps["traceroute6"].status == SKIP and steps["ports6"].status == SKIP
    assert steps["ports"].status == OK


def test_ipv6_literal_target_skips_ipv4_target_steps():
    steps = run_all(FakeNet(v6=True), target="2606:2800:21f:cb07:6820:80da:af6b:8b2c")[0]
    assert steps["traceroute"].status == SKIP and steps["ports"].status == SKIP
    assert steps["ports6"].status == OK


def test_ipv6_working_while_ipv4_is_dead_still_blames_the_isp_but_says_so():
    dead4 = {None: TIMEOUT, "1.1.1.1": TIMEOUT, "8.8.8.8": TIMEOUT}
    net = FakeNet(v6=True, cf_ping=S.PING_LINUX_DEAD, g_ping=S.PING_LINUX_DEAD, dns=dead4,
                  trace=S.TRACE_UNIX_STALLED, ports={80: "filtered", 443: "filtered"})
    _, v, _ = run_all(net)
    assert (v.layer, v.status) == ("isp", FAIL)
    assert any("IPv6 works even though IPv4 doesn't" in e for e in v.evidence)


# ----------------------------------------------------- real local sockets
def test_tcp_probe_open_then_closed_on_localhost():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    assert checks.tcp_probe("127.0.0.1", port, 2, 4).state == "open"
    srv.close()
    assert checks.tcp_probe("127.0.0.1", port, 2, 4).state == "closed"


def test_tcp_probe_unresolvable_name_is_noaddr_for_v6_and_error_for_v4():
    # ".invalid" is reserved and can never resolve, on any machine.
    assert checks.tcp_probe("nosuchhost.invalid", 80, 1, 6).state == "noaddr"
    assert checks.tcp_probe("nosuchhost.invalid", 80, 1, 4).state == "error"


# ---------------------------------------------------------------- CLI
def make_console():
    return Console(file=io.StringIO(), width=100, force_terminal=False, color_system=None)


def factory_for(net):
    def factory(**kw):
        ctx = net.context(target=kw["target"], ipv6=kw["ipv6"])
        ctx.ports, ctx.dns_name = kw["ports"], kw["dns_name"]
        return ctx
    return factory


@pytest.mark.parametrize("ok", ["2606:2800:21f:cb07:6820:80da:af6b:8b2c", "::1", "93.184.216.34"])
def test_target_accepts_ip_literals(ok):
    assert cli.valid_target(ok) == ok


@pytest.mark.parametrize("bad", ["fe80::1%en0", "-::1", ":::", "g::1"])
def test_target_rejects_scoped_and_malformed_ipv6(bad):
    with pytest.raises(argparse.ArgumentTypeError):
        cli.valid_target(bad)


def test_ipv6_flag_defaults_on():
    assert cli.build_parser().parse_args([]).ipv6 is True
    assert cli.build_parser().parse_args(["--no-ipv6"]).ipv6 is False


def test_cli_shows_ipv6_steps_with_a_dynamic_total():
    console = make_console()
    assert cli.main([], console, factory_for(FakeNet(v6=True))) == 0
    out = console.file.getvalue()
    assert "[1/11]" in out and "[11/11]" in out
    assert "$ ping -6 -c 4" in out and "IPv6 gateway ping" in out


def test_cli_without_ipv6_keeps_six_steps():
    console = make_console()
    cli.main([], console, factory_for(FakeNet()))
    out = console.file.getvalue()
    assert "[6/6]" in out and "IPv6 gateway" not in out


def test_cli_no_ipv6_flag():
    console = make_console()
    cli.main(["--no-ipv6"], console, factory_for(FakeNet(v6=True)))
    out = console.file.getvalue()
    assert "[6/6]" in out and "IPv6 internet" not in out


def test_watch_forgets_ipv6_between_runs_if_it_disappears():
    net = FakeNet(v6=True)
    sleeps = []

    def fake_sleep(n):
        sleeps.append(n)
        if len(sleeps) == 1:
            net.ifaces = S.IFACES_IP  # the IPv6 address vanishes between runs
        else:
            raise KeyboardInterrupt

    console = make_console()
    cli.main(["--watch", "5", "--quiet"], console, factory_for(net), fake_sleep)
    assert console.file.getvalue().count("IPv6 gateway ping") == 1  # run 1 only


def test_nslookup_macos_has_aaaa_address_format():
    r = parsers.parse_nslookup(S.NSLOOKUP_AAAA_MAC, 6)
    assert r.ok and r.answers == ["2607:f8b0:4009:803::200e"]
    assert not parsers.parse_nslookup(S.NSLOOKUP_AAAA_MAC, 4).ok  # right family only
    assert parsers.parse_nslookup(S.NSLOOKUP_A_MAC_TYPED, 4).answers == ["142.250.80.46"]


def test_ipv6_titles_keep_acronyms_intact(healthy6):
    steps = run_all(healthy6)[0]
    assert steps["ports6"].title == "IPv6 TCP port checks on example.com"
    assert steps["gateway6"].title == "IPv6 gateway ping"
    assert steps["traceroute6"].title == "IPv6 traceroute to example.com"
