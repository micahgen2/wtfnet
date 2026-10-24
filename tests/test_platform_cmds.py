from wtfnet import platform_cmds as pc
from wtfnet.runner import format_command


def test_ping_flags_differ_per_os():
    assert pc.ping_cmd("1.1.1.1", "windows")[:3] == ["ping", "-n", "4"]
    assert pc.ping_cmd("1.1.1.1", "linux")[:3] == ["ping", "-c", "4"]
    assert pc.ping_cmd("1.1.1.1", "darwin")[:3] == ["ping", "-c", "4"]
    assert pc.ping_cmd("1.1.1.1", "linux")[-1] == "1.1.1.1"


def test_windows_uses_tracert_others_use_traceroute():
    assert pc.traceroute_cmd("x.com", "windows")[0] == "tracert"
    assert pc.traceroute_cmd("x.com", "linux")[0] == "traceroute"


def test_linux_falls_back_to_ifconfig_and_netstat_without_iproute2():
    no_ip = lambda name: None
    assert pc.interfaces_cmd("linux", no_ip) == ["ifconfig"]
    assert pc.gateway_cmd("linux", no_ip) == ["netstat", "-rn"]
    assert pc.interfaces_cmd("linux", lambda n: "/bin/" + n)[0] == "ip"


def test_nslookup_with_and_without_server():
    assert pc.nslookup_cmd("a.com")[-1] == "a.com"
    assert pc.nslookup_cmd("a.com", "1.1.1.1")[-2:] == ["a.com", "1.1.1.1"]


def test_commands_are_lists_not_shell_strings():
    # A hostile "hostname" stays a single argv element, never shell syntax.
    cmd = pc.ping_cmd("x; rm -rf ~", "linux")
    assert cmd[-1] == "x; rm -rf ~"
    assert "'x; rm -rf ~'" in format_command(cmd, "linux")  # quoted when displayed
