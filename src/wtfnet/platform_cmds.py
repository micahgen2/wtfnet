"""Which command to run on which operating system.

Windows, macOS and Linux all have a `ping`, but they disagree on the flags.
Example: "send 4 packets" is `-n 4` on Windows and `-c 4` everywhere else.
Keeping every OS difference in this one file means the rest of the program
never has to care what it's running on.

Every function returns an argv *list* (["ping", "-c", "4", host]) rather than
a single string. We never hand these to a shell, so a malicious "hostname"
can't smuggle in extra commands.

IPv6 differences worth knowing:
  * macOS has separate `ping6` / `traceroute6` programs.
  * Linux and Windows use the normal programs with a `-6` flag.
"""

from __future__ import annotations

import platform
import shutil
from typing import Callable, List, Optional

PING_COUNT = 4

Which = Callable[[str], Optional[str]]


def detect_system() -> str:
    """Return 'windows', 'darwin' (macOS) or 'linux'."""
    name = platform.system().lower()
    return name if name in ("windows", "darwin") else "linux"


def interfaces_cmd(system: str, which: Which = shutil.which) -> List[str]:
    """One command that lists both IPv4 and IPv6 addresses."""
    if system == "windows":
        return ["ipconfig", "/all"]
    if system == "linux" and which("ip"):
        # -o = one line per address. Far less noise than ifconfig.
        return ["ip", "-o", "addr", "show"]
    return ["ifconfig"]


def gateway_cmd(system: str, which: Which = shutil.which) -> List[str]:
    """Ask the OS for its routing table's default route (the 'gateway')."""
    if system == "windows":
        return ["route", "print", "-4", "0.0.0.0"]
    if system == "darwin":
        return ["route", "-n", "get", "default"]
    if which("ip"):
        return ["ip", "route", "show", "default"]
    return ["netstat", "-rn"]


def gateway6_cmd(system: str, which: Which = shutil.which) -> List[str]:
    if system == "windows":
        return ["route", "print", "-6"]
    if system == "darwin":
        return ["route", "-n", "get", "-inet6", "default"]
    if which("ip"):
        return ["ip", "-6", "route", "show", "default"]
    return ["netstat", "-rn", "-A", "inet6"]


def wifi_cmd(system: str, which: Which = shutil.which) -> List[str]:
    """Wi-Fi link details (signal, channel, speed)."""
    if system == "darwin":
        # `airport -I` was removed from macOS and `networksetup` misreports. This is slow (~10s)
        # because it scans for nearby networks, but it's the only thing that works.
        return ["system_profiler", "-detailLevel", "basic", "SPAirPortDataType"]
    if system == "windows":
        return ["netsh", "wlan", "show", "interfaces"]
    if which("nmcli"):
        return ["nmcli", "-t", "-f", "ACTIVE,SSID,CHAN,FREQ,RATE,SIGNAL", "dev", "wifi"]
    return ["iwconfig"]


def wifi_flavor(argv: List[str]) -> str:
    return {"system_profiler": "macos", "netsh": "netsh", "nmcli": "nmcli"}.get(argv[0], "iwconfig")


def hwports_cmd() -> List[str]:
    """macOS: lists which device (en0, en1...) is the Wi-Fi card."""
    return ["networksetup", "-listallhardwareports"]


def ping_cmd(host: str, system: str, count: int = PING_COUNT, family: int = 4) -> List[str]:
    if system == "windows":
        return ["ping"] + (["-6"] if family == 6 else []) + ["-n", str(count), "-w", "2000", host]
    if system == "darwin":
        if family == 6:
            return ["ping6", "-c", str(count), host]
        # macOS: -t is a total deadline in seconds.
        return ["ping", "-c", str(count), "-t", "10", host]
    # Linux: -W is per-packet wait, -w is the total deadline, both in seconds.
    return ["ping"] + (["-6"] if family == 6 else []) + ["-c", str(count), "-W", "2", "-w", "10", host]


def traceroute_cmd(host: str, system: str, max_hops: int = 20, family: int = 4) -> List[str]:
    if system == "windows":
        # -d = don't look up hostnames (much faster), -w = ms to wait per probe.
        return ["tracert"] + (["-6"] if family == 6 else []) + ["-d", "-h", str(max_hops), "-w", "2000", host]
    # -n = numeric only, -q 2 = 2 probes per hop, -w 2 = 2s wait per probe.
    tail = ["-n", "-m", str(max_hops), "-q", "2", "-w", "2", host]
    if family == 6:
        return ["traceroute6"] + tail if system == "darwin" else ["traceroute", "-6"] + tail
    return ["traceroute"] + tail


def nslookup_cmd(name: str, server: Optional[str] = None, rtype: Optional[str] = None) -> List[str]:
    """nslookup exists on all three OSes. `server` picks a specific resolver;
    `rtype` picks the record type (AAAA = the IPv6 address record)."""
    cmd = ["nslookup", "-timeout=3", "-retry=1"]
    if rtype:
        cmd.append("-type=" + rtype)
    cmd.append(name)
    if server:
        cmd.append(server)
    return cmd
