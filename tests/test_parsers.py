import samples as S

from wtfnet import parsers


# ----------------------------------------------------------------- ping
def test_ping_linux():
    s = parsers.parse_ping(S.PING_LINUX_OK, "linux")
    assert (s.sent, s.received, s.loss_pct) == (4, 4, 0)
    assert (s.min_ms, s.avg_ms, s.max_ms) == (10.9, 11.3, 12.0)


def test_ping_macos_uses_packets_received_wording():
    s = parsers.parse_ping(S.PING_MAC_OK, "darwin")
    assert (s.sent, s.received) == (4, 4)
    assert s.avg_ms == 11.312


def test_ping_windows():
    s = parsers.parse_ping(S.PING_WIN_OK, "windows")
    assert (s.sent, s.received, s.avg_ms) == (4, 4, 11.0)


def test_ping_partial_loss():
    s = parsers.parse_ping(S.PING_LINUX_LOSSY, "linux")
    assert s.loss_pct == 50


def test_ping_total_loss_has_no_rtt():
    s = parsers.parse_ping(S.PING_LINUX_DEAD, "linux")
    assert s.received == 0 and s.loss_pct == 100 and s.avg_ms is None


def test_ping_windows_unreachable_is_not_counted_as_received():
    s = parsers.parse_ping(S.PING_WIN_UNREACHABLE, "windows")
    assert s.received == 0 and s.loss_pct == 100


def test_ping_unresolvable_host():
    s = parsers.parse_ping(S.PING_LINUX_UNRESOLVED, "linux")
    assert s.unresolved and s.received == 0


def test_ping_garbage_returns_none():
    assert parsers.parse_ping("ping: permission denied, go away", "linux") is None


# -------------------------------------------------------------- gateway
def test_gateway_all_formats():
    assert parsers.parse_gateway(S.GATEWAY_LINUX) == "192.168.1.1"
    assert parsers.parse_gateway(S.GATEWAY_MAC) == "192.168.1.1"
    assert parsers.parse_gateway(S.GATEWAY_NETSTAT) == "192.168.1.1"


def test_gateway_windows_picks_lowest_metric():
    assert parsers.parse_gateway(S.GATEWAY_WIN) == "192.168.1.1"  # metric 25 beats 50


def test_gateway_missing():
    assert parsers.parse_gateway("") is None
    assert parsers.parse_gateway("interface: utun3\n") is None


# ----------------------------------------------------------- interfaces
def test_interfaces_ip_skips_loopback():
    got = parsers.parse_interfaces(S.IFACES_IP, "ip")
    assert [(i.name, i.ip) for i in got] == [("wlan0", "192.168.1.23")]


def test_interfaces_ifconfig():
    got = parsers.parse_interfaces(S.IFACES_IFCONFIG, "ifconfig")
    assert [(i.name, i.ip) for i in got] == [("en0", "192.168.1.23")]


def test_interfaces_ipconfig():
    got = parsers.parse_interfaces(S.IFACES_IPCONFIG, "ipconfig")
    assert [(i.name, i.ip) for i in got] == [("Wireless LAN adapter Wi-Fi", "192.168.1.23")]


def test_interfaces_link_local_flag():
    got = parsers.parse_interfaces(S.IFACES_IP_LINKLOCAL, "ip")
    assert got[0].is_link_local


# ------------------------------------------------------------------ DNS
def test_nslookup_unix_ignores_server_address():
    r = parsers.parse_nslookup(S.NSLOOKUP_UNIX_OK)
    assert r.ok and r.answers == ["93.184.216.34"]


def test_nslookup_windows_skips_ipv6_and_server():
    r = parsers.parse_nslookup(S.NSLOOKUP_WIN_OK)
    assert r.answers == ["93.184.216.34"]


def test_nslookup_failures_are_classified():
    assert parsers.parse_nslookup(S.NSLOOKUP_NXDOMAIN).error == "nxdomain"
    assert parsers.parse_nslookup(S.NSLOOKUP_TIMEOUT).error == "timeout"


# ----------------------------------------------------------- traceroute
def test_traceroute_unix_reached():
    t = parsers.parse_traceroute(S.TRACE_UNIX_REACHED, "example.com")
    assert t.reached and t.dest_ip == "93.184.216.34"
    assert len(t.hops) == 4 and t.hops[2].ip is None  # the "* *" hop
    assert t.hops[0].rtt_ms == 1.1


def test_traceroute_unix_stalled():
    t = parsers.parse_traceroute(S.TRACE_UNIX_STALLED, "example.com")
    assert not t.reached and len(t.responding) == 2


def test_traceroute_windows_reached_and_lt1ms():
    t = parsers.parse_traceroute(S.TRACE_WIN_REACHED, "example.com")
    assert t.reached and t.hops[0].rtt_ms == 1.0 and t.hops[2].ip is None
