"""End-to-end: run the whole battery against a fake network and check the blame."""

import samples as S
from conftest import FakeNet, GW

from wtfnet.checks import STEPS
from wtfnet.models import FAIL, OK, SKIP, WARN
from wtfnet.verdict import compute_verdict


def diagnose(net):
    ctx = net.context()
    results = [step.fn(ctx) for step in STEPS]
    return {r.key: r for r in results}, compute_verdict(results, ctx.target)


DEAD = S.PING_LINUX_DEAD


def test_healthy_network(healthy):
    steps, v = diagnose(healthy)
    assert all(s.status == OK for s in steps.values())
    assert (v.layer, v.status) == ("none", OK)


def test_every_step_shows_the_exact_command_and_raw_output(healthy):
    steps, _ = diagnose(healthy)
    gw = steps["gateway"]
    assert gw.execs[0].display == "ip route show default"
    assert gw.execs[1].display.startswith("ping -c 4")
    assert "192.168.1.1" in gw.execs[1].output
    assert steps["traceroute"].execs[0].display.startswith("traceroute -n")


def test_no_ip_address_is_a_local_problem():
    net = FakeNet(ifaces="1: lo    inet 127.0.0.1/8 scope host lo\\\n", gateway="",
                  gw_ping=DEAD, cf_ping=DEAD, g_ping=DEAD, trace="traceroute: sendto: Network is unreachable\n",
                  dns={None: S.NSLOOKUP_TIMEOUT, "1.1.1.1": S.NSLOOKUP_TIMEOUT, "8.8.8.8": S.NSLOOKUP_TIMEOUT},
                  ports={80: "error", 443: "error"})
    _, v = diagnose(net)
    assert (v.layer, v.status) == ("local", FAIL)


def test_dhcp_failure_169_254_is_local():
    net = FakeNet(ifaces=S.IFACES_IP_LINKLOCAL, gateway="", gw_ping=DEAD, cf_ping=DEAD, g_ping=DEAD,
                  dns={None: S.NSLOOKUP_TIMEOUT, "1.1.1.1": S.NSLOOKUP_TIMEOUT, "8.8.8.8": S.NSLOOKUP_TIMEOUT},
                  ports={80: "filtered", 443: "filtered"})
    steps, v = diagnose(net)
    assert steps["interfaces"].data["link_local"]
    assert v.layer == "local"


def test_dead_router_is_a_gateway_problem():
    net = FakeNet(gw_ping=DEAD, cf_ping=DEAD, g_ping=DEAD,
                  dns={None: S.NSLOOKUP_TIMEOUT, "1.1.1.1": S.NSLOOKUP_TIMEOUT, "8.8.8.8": S.NSLOOKUP_TIMEOUT},
                  trace=S.TRACE_UNIX_STALLED.replace("192.168.1.1  1.234 ms  1.100 ms", "* *"),
                  ports={80: "filtered", 443: "filtered"})
    _, v = diagnose(net)
    assert (v.layer, v.status) == ("gateway", FAIL)


def test_router_fine_but_internet_dead_is_isp():
    net = FakeNet(cf_ping=DEAD, g_ping=DEAD, trace=S.TRACE_UNIX_STALLED,
                  dns={None: S.NSLOOKUP_TIMEOUT, "1.1.1.1": S.NSLOOKUP_TIMEOUT, "8.8.8.8": S.NSLOOKUP_TIMEOUT},
                  ports={80: "filtered", 443: "filtered"})
    steps, v = diagnose(net)
    assert steps["gateway"].status == OK
    assert (v.layer, v.status) == ("isp", FAIL)


def test_system_resolver_broken_is_dns():
    net = FakeNet(dns={None: S.NSLOOKUP_TIMEOUT},
                  ports={80: "open", 443: "open"})
    steps, v = diagnose(net)
    assert steps["dns"].status == FAIL
    assert (v.layer, v.status) == ("dns", FAIL)


def test_slow_system_resolver_is_a_dns_warning():
    net = FakeNet()
    slow = net.__call__

    def slow_run(argv, timeout=30):
        res = slow(argv, timeout)
        if argv[0] == "nslookup":
            res.elapsed = 0.9 if len(argv) == 4 else 0.02  # system (no server arg) is slow
        return res

    ctx = net.context()
    ctx.run = slow_run
    results = [s.fn(ctx) for s in STEPS]
    v = compute_verdict(results, ctx.target)
    assert (v.layer, v.status) == ("dns", WARN)


def test_server_down_is_remote():
    net = FakeNet(ports={80: "filtered", 443: "filtered"}, trace=S.TRACE_UNIX_STALLED)
    steps, v = diagnose(net)
    assert steps["ports"].status == FAIL
    assert (v.layer, v.status) == ("remote", FAIL)


def test_refused_ports_prove_host_is_reachable_but_still_remote_fail():
    net = FakeNet(ports={80: "closed", 443: "closed"})
    steps, v = diagnose(net)
    assert steps["ports"].data["reachable_count"] == 2
    assert v.layer == "remote"


def test_one_port_open_is_a_remote_warning():
    _, v = diagnose(FakeNet(ports={80: "open", 443: "filtered"}))
    assert (v.layer, v.status) == ("remote", WARN)


def test_lossy_wifi_is_gateway_degraded():
    net = FakeNet(gw_ping=S.PING_LINUX_LOSSY)
    _, v = diagnose(net)
    assert (v.layer, v.status) == ("gateway", WARN)


def test_icmp_blocked_everywhere_but_traffic_flows_is_not_blamed_on_isp():
    # Corporate-style network: every ping dies, yet DNS and TCP work fine.
    net = FakeNet(gw_ping=DEAD, cf_ping=DEAD, g_ping=DEAD, trace=S.TRACE_UNIX_STALLED)
    steps, v = diagnose(net)
    assert steps["internet"].status == FAIL
    assert (v.layer, v.status) == ("none", OK)
    assert any("harmless" in e for e in v.evidence)


def test_missing_tools_are_skipped_not_crashed():
    net = FakeNet(missing={"ping", "traceroute", "nslookup"})
    steps, v = diagnose(net)
    assert steps["internet"].status == SKIP
    assert steps["traceroute"].status == SKIP
    assert steps["dns"].status == FAIL or steps["dns"].status == OK  # falls back to socket resolver
    assert "socket.getaddrinfo" in steps["dns"].execs[0].display


def test_everything_missing_is_inconclusive():
    net = FakeNet(missing={"ip", "ping", "traceroute", "nslookup"})
    ctx = net.context()
    ctx.tcp_connect = None  # not reached; replace ports step with a skip
    results = [s.fn(ctx) for s in STEPS[:5]]
    results = [r for r in results if r.key != "dns"]  # dns would fall back to sockets
    v = compute_verdict(results, "example.com")
    assert v.layer == "none" and v.status == WARN
