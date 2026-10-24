"""Turn the raw text printed by ping/traceroute/etc. into structured data.

These are pure functions (text in, data out) with no I/O, which makes them
trivial to test against saved samples of each OS's output.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import List, Optional

IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"


# --------------------------------------------------------------------- ping
@dataclass
class PingStats:
    sent: int
    received: int
    min_ms: Optional[float] = None
    avg_ms: Optional[float] = None
    max_ms: Optional[float] = None
    unresolved: bool = False  # the hostname itself couldn't be looked up

    @property
    def loss_pct(self) -> float:
        if self.sent <= 0:
            return 100.0
        return round(100.0 * (self.sent - self.received) / self.sent, 1)


_REPLY = re.compile(r"ttl=\d+|hlim=\d+|reply from \S+: (?:bytes=\d+ )?time[=<]")

_UNRESOLVED = (
    "unknown host",
    "cannot resolve",
    "could not find host",
    "name or service not known",
    "nodename nor servname",
    "temporary failure in name resolution",
)


def parse_ping(text: str, system: str, expected_sent: int = 4) -> Optional[PingStats]:
    """Parse Linux, macOS or Windows ping output. Returns None if unreadable."""
    low = text.lower()
    unresolved = any(s in low for s in _UNRESOLVED)
    # Count real reply lines: "ttl=57" (IPv4), "hlim=57" (macOS IPv6), or
    # "Reply from X: time=11ms" (Windows IPv6 has no TTL at all).
    replies = sum(1 for line in low.splitlines() if _REPLY.search(line))

    sent = received = None
    # Linux: "4 packets transmitted, 4 received"; macOS: "... 4 packets received"
    m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", low)
    if m:
        sent, received = int(m.group(1)), int(m.group(2))
    else:
        m = re.search(r"sent = (\d+), received = (\d+)", low)  # Windows
        if m:
            sent = int(m.group(1))
            # Windows counts "Destination host unreachable" replies as
            # "Received", which is a lie. Real replies carry a TTL.
            received = replies

    if sent is None:
        # No summary line: the command probably died early.
        if not (replies or unresolved or re.search(r"timed out|unreachable|100%|no answer", low)):
            return None
        sent, received = expected_sent, replies

    stats = PingStats(sent, received, unresolved=unresolved)
    if received:
        m = re.search(
            r"min/avg/max(?:/(?:mdev|stddev|std-dev))?\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)", low
        )
        if m:
            stats.min_ms, stats.avg_ms, stats.max_ms = (float(g) for g in m.groups())
        else:
            m = re.search(r"minimum = (\d+)ms, maximum = (\d+)ms, average = (\d+)ms", low)
            if m:
                stats.min_ms, stats.max_ms, stats.avg_ms = (float(g) for g in m.groups())
    return stats


# ------------------------------------------------------------------ gateway
def parse_gateway(text: str) -> Optional[str]:
    """Find the default gateway IP in the output of any OS's route command."""
    # Linux `ip route show default`: "default via 192.168.1.1 dev eth0 ..."
    m = re.search(rf"default via ({IPV4})", text)
    if m:
        return m.group(1)
    # macOS `route -n get default`: "    gateway: 192.168.1.1"
    m = re.search(rf"gateway:\s*({IPV4})", text)
    if m:
        return m.group(1)
    # Windows `route print`: "0.0.0.0  0.0.0.0  192.168.1.1  192.168.1.23  25"
    # (last column = metric; if there are several default routes, lowest wins)
    best = None
    for m in re.finditer(rf"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+({IPV4})\s+{IPV4}\s+(\d+)", text, re.M):
        if best is None or int(m.group(2)) < best[1]:
            best = (m.group(1), int(m.group(2)))
    if best:
        return best[0]
    # Linux `netstat -rn` fallback: "0.0.0.0  192.168.1.1  0.0.0.0  UG ..."
    m = re.search(rf"^0\.0\.0\.0\s+({IPV4})\s+0\.0\.0\.0", text, re.M)
    if m:
        return m.group(1)
    return None


# --------------------------------------------------------------- interfaces
@dataclass
class Interface:
    name: str
    ip: str

    @property
    def is_link_local(self) -> bool:
        # 169.254.x.x = "DHCP never answered so I invented an address" (APIPA)
        return self.ip.startswith("169.254.")


def parse_interfaces(text: str, flavor: str) -> List[Interface]:
    """flavor: 'ip' (Linux iproute2), 'ifconfig' (macOS/old Linux), 'ipconfig' (Windows)."""
    found: List[Interface] = []
    if flavor == "ip":
        for m in re.finditer(rf"^\d+:\s+(\S+)\s+inet\s+({IPV4})", text, re.M):
            found.append(Interface(m.group(1), m.group(2)))
    elif flavor == "ifconfig":
        current = None
        for line in text.splitlines():
            if line and not line[0].isspace():
                current = re.match(r"[^\s:]+", line).group(0)
                continue
            m = re.match(rf"\s+inet (?:addr:)?({IPV4})", line)
            if m and current:
                found.append(Interface(current, m.group(1)))
    elif flavor == "ipconfig":
        current = None
        for line in text.splitlines():
            if line and not line[0].isspace() and line.rstrip().endswith(":"):
                current = line.rstrip()[:-1]  # e.g. "Wireless LAN adapter Wi-Fi"
                continue
            m = re.search(rf"IPv4 Address[ .]*:\s*({IPV4})", line)
            if m and current:
                found.append(Interface(current, m.group(1)))
    return [i for i in found if not i.ip.startswith("127.")]


# -------------------------------------------------------------------- IPv6
def _norm_ip(text: str) -> Optional[str]:
    """Canonical form of an IP ('2606:4700:0:0::1' == '2606:4700::1'), or None."""
    try:
        return str(ipaddress.ip_address(text.split("%")[0]))
    except ValueError:
        return None


def ip_family(text: str) -> Optional[int]:
    """4 or 6 if `text` is an IP literal, None if it's a hostname."""
    try:
        return ipaddress.ip_address(text).version
    except ValueError:
        return None


@dataclass
class Interface6:
    name: str
    ip: str

    @property
    def is_link_local(self) -> bool:
        return self.ip.lower().startswith("fe80")  # every interface has one; proves nothing

    @property
    def is_global(self) -> bool:
        # Globally routable only: excludes fe80:: (link-local) and fd00::/8 (private "ULA").
        try:
            return ipaddress.IPv6Address(self.ip).is_global
        except ValueError:
            return False


def parse_interfaces6(text: str, flavor: str) -> List[Interface6]:
    """IPv6 addresses, same flavors as parse_interfaces. Loopback is dropped."""
    found: List[Interface6] = []

    def add(name: str, raw: str) -> None:
        raw = raw.split("%")[0]
        try:
            ipaddress.IPv6Address(raw)
        except ValueError:
            return
        if raw != "::1":
            found.append(Interface6(name, raw))

    if flavor == "ip":
        for m in re.finditer(r"^\d+:\s+(\S+)\s+inet6\s+([0-9a-fA-F:]+)", text, re.M):
            add(m.group(1), m.group(2))
    elif flavor == "ifconfig":
        current = None
        for line in text.splitlines():
            if line and not line[0].isspace():
                current = re.match(r"[^\s:]+", line).group(0)
                continue
            m = re.match(r"\s+inet6 (?:addr:\s*)?([0-9a-fA-F:]+)", line)
            if m and current:
                add(current, m.group(1))
    elif flavor == "ipconfig":
        current = None
        for line in text.splitlines():
            if line and not line[0].isspace() and line.rstrip().endswith(":"):
                current = line.rstrip()[:-1]
                continue
            # Also matches "Temporary IPv6 Address" and "Link-local IPv6 Address".
            m = re.search(r"IPv6 Address[ .]*:\s*([0-9a-fA-F:]+)", line)
            if m and current:
                add(current, m.group(1))
    return found


def parse_default_route6(text: str) -> Optional[str]:
    """Default IPv6 gateway, with a %scope when it's link-local (needed to ping it)."""

    def scoped(gw: str, scope: Optional[str]) -> str:
        if "%" not in gw and scope and gw.lower().startswith("fe80"):
            return "{}%{}".format(gw, scope)
        return gw

    # Linux `ip -6 route show default`: "default via fe80::1 dev wlan0 proto ra ..."
    m = re.search(r"^default via ([0-9a-fA-F:]+)(?:\s+dev (\S+))?", text, re.M)
    if m and ":" in m.group(1):
        return scoped(m.group(1), m.group(2))
    # macOS `route -n get -inet6 default`: "    gateway: fe80::1%en0"
    m = re.search(r"gateway:\s*([0-9a-fA-F:]+(?:%\S+)?)", text)
    if m and ":" in m.group(1):
        return m.group(1)
    # Windows `route print -6`: " 12    281 ::/0      fe80::1" (first column = interface index)
    m = re.search(r"^\s*(\d+)\s+\d+\s+::/0\s+(\S+)", text, re.M)
    if m and ":" in m.group(2):
        return scoped(m.group(2), m.group(1))
    # Linux `netstat -rn -A inet6`: "::/0   fe80::1   UG   1024 ... wlan0"
    m = re.search(r"^::/0\s+(\S+)\s+.*?(\S+)\s*$", text, re.M)
    if m and ":" in m.group(1):
        return scoped(m.group(1), m.group(2))
    return None


# --------------------------------------------------------------------- DNS
@dataclass
class DnsResult:
    answers: List[str] = field(default_factory=list)
    error: Optional[str] = None  # nxdomain | timeout | refused | servfail | unknown

    @property
    def ok(self) -> bool:
        return bool(self.answers)


def parse_nslookup(text: str, family: int = 4) -> DnsResult:
    """family=4 collects A records, family=6 collects AAAA records."""
    answers: List[str] = []
    # macOS prints typed lookups as "google.com  has AAAA address 2607:f8b0::200e"
    # (or "has address 1.2.3.4") with no "Name:" line at all.
    for token in re.findall(r"\bhas (?:AAAA )?address (\S+)", text):
        if ip_family(token) == family and token not in answers:
            answers.append(token)
    # Everything before the first "Name:" line describes the *server* we asked,
    # not the answer, so skip it.
    m = re.search(r"^Name:", text, re.M)
    if m:
        tail = text[m.start():]
        if family == 4:
            candidates = re.findall(IPV4, tail)
        else:
            candidates = []
            for token in re.split(r"[\s,]+", tail):
                token = token.split("#")[0]
                try:
                    ipaddress.IPv6Address(token)
                except ValueError:
                    continue
                candidates.append(token)
        for ip in candidates:
            if ip not in answers:
                answers.append(ip)
    if answers:
        return DnsResult(answers)

    low = text.lower()
    if "nxdomain" in low or "non-existent domain" in low or "server can't find" in low:
        err = "nxdomain"
    elif "timed out" in low or "timed-out" in low or "no servers could be reached" in low:
        err = "timeout"
    elif "refused" in low:
        err = "refused"
    elif "servfail" in low or "server failure" in low:
        err = "servfail"
    elif "no answer" in low or re.search(r"^server:", low, re.M):
        err = "noanswer"  # the server replied; it just had no record of that type
    else:
        err = "unknown"
    return DnsResult([], err)


# -------------------------------------------------------------- traceroute
@dataclass
class Hop:
    n: int
    ip: Optional[str]  # None = every probe timed out (the "* * *" lines)
    rtt_ms: Optional[float]  # fastest probe


@dataclass
class TraceResult:
    hops: List[Hop]
    dest_ip: Optional[str]
    reached: bool

    @property
    def responding(self) -> List[Hop]:
        return [h for h in self.hops if h.ip]


def parse_traceroute(text: str, target: Optional[str] = None) -> TraceResult:
    hops: List[Hop] = []
    for line in text.splitlines():
        m = re.match(r"\s*(\d+)\s+(.*)$", line)
        if not m:
            continue
        rest = m.group(2)
        ip = next((n for n in map(_norm_ip, re.split(r"[\s()\[\],]+", rest)) if n), None)
        rtts = [float(x.lstrip("<")) for x in re.findall(r"(<?\d+(?:\.\d+)?)\s*ms", rest)]
        hops.append(Hop(int(m.group(1)), ip, min(rtts) if rtts else None))

    # The first lines name the destination: "traceroute to x (1.2.3.4)" or
    # "Tracing route to x [1.2.3.4]".
    dest = None
    head = "\n".join(text.splitlines()[:3])
    m = re.search(r"[\[(]([0-9a-fA-F:.]+)[\])]", head) or re.search(r"\bto ([0-9a-fA-F:.]+)", head)
    if m:
        dest = _norm_ip(m.group(1))
    if dest is None and target:
        dest = _norm_ip(target)  # None unless the target is itself an IP literal

    # NB: Windows prints "Trace complete." even when it gave up, so we only
    # trust "a hop answered from the destination's own IP".
    reached = bool(dest and any(h.ip == dest for h in hops))
    return TraceResult(hops, dest, reached)


# -------------------------------------------------------------------- Wi-Fi
@dataclass
class WifiInfo:
    connected: bool
    ssid: Optional[str] = None  # None when the OS hides it (macOS without Location permission)
    signal_dbm: Optional[float] = None
    noise_dbm: Optional[float] = None
    channel: Optional[int] = None
    band: Optional[str] = None  # "2.4 GHz" | "5 GHz" | "6 GHz"
    rate_mbps: Optional[float] = None
    phy: Optional[str] = None  # e.g. "802.11ax"

    @property
    def snr_db(self) -> Optional[float]:
        """Signal-to-noise ratio: how far your signal stands above the background hiss."""
        if self.signal_dbm is None or self.noise_dbm is None:
            return None
        return self.signal_dbm - self.noise_dbm


def _pct_to_dbm(pct: float) -> float:
    return pct / 2.0 - 100.0  # the usual rough conversion: 100% = -50 dBm, 0% = -100 dBm


def _band_from_ghz(ghz: float) -> str:
    return "2.4 GHz" if ghz < 3 else "5 GHz" if ghz < 5.9 else "6 GHz"


def _num(text: Optional[str]) -> Optional[float]:
    try:
        return float(text) if text is not None else None
    except ValueError:
        return None


def _real_ssid(raw: Optional[str]) -> Optional[str]:
    raw = (raw or "").strip()
    return None if not raw or "redacted" in raw.lower() else raw


def parse_wifi_macos(text: str) -> Optional[WifiInfo]:
    """`system_profiler SPAirPortDataType`: the only thing that still works on modern macOS."""
    if not re.search(r"^\s*Status:", text, re.M):
        return None
    if not re.search(r"^\s*Status:\s*Connected", text, re.M):
        return WifiInfo(False)
    m = re.search(
        r"Current Network Information:\s*\n(.*?)(?=\n\s*Other Local Wi-Fi Networks:|\n\s*Current Network Information:|\Z)",
        text, re.S)
    if not m:
        return WifiInfo(True)
    block = m.group(1)
    info = WifiInfo(True)
    first = re.match(r"\s*([^\n]+?):\s*(?:\n|$)", block)
    info.ssid = _real_ssid(first.group(1)) if first else None
    g = re.search(r"PHY Mode:\s*(\S+)", block)
    info.phy = g.group(1) if g else None
    g = re.search(r"Channel:\s*(\d+)\s*\((\d)\s*GHz", block)
    if g:
        info.channel = int(g.group(1))
        info.band = {"2": "2.4 GHz", "5": "5 GHz", "6": "6 GHz"}.get(g.group(2))
    g = re.search(r"Signal / Noise:\s*(-?\d+)\s*dBm\s*/\s*(-?\d+)\s*dBm", block)
    if g:
        info.signal_dbm, info.noise_dbm = float(g.group(1)), float(g.group(2))
    g = re.search(r"Transmit Rate:\s*([\d.]+)", block)
    info.rate_mbps = _num(g.group(1)) if g else None
    return info


def parse_wifi_nmcli(text: str) -> Optional[WifiInfo]:
    """`nmcli -t -f ACTIVE,SSID,CHAN,FREQ,RATE,SIGNAL dev wifi` (terse: colon-separated)."""
    rows = []
    for line in text.splitlines():
        parts = [p.replace("\\:", ":") for p in re.split(r"(?<!\\):", line)]
        if len(parts) >= 6:
            rows.append(parts)
    if not rows:
        return None
    active = [r for r in rows if r[0].lower() == "yes"]
    if not active:
        return WifiInfo(False)
    _, ssid, chan, freq, rate, signal = active[0][:6]
    info = WifiInfo(True, ssid=_real_ssid(ssid))
    info.channel = int(chan) if chan.isdigit() else None
    mhz = _num(re.sub(r"[^\d.]", "", freq) or None)
    info.band = _band_from_ghz(mhz / 1000.0) if mhz else None
    info.rate_mbps = _num(re.sub(r"[^\d.]", "", rate) or None)
    pct = _num(signal)
    info.signal_dbm = _pct_to_dbm(pct) if pct is not None else None
    return info


def parse_wifi_iwconfig(text: str) -> Optional[WifiInfo]:
    """`iwconfig` (older Linux without NetworkManager)."""
    for block in re.split(r"\n(?=\S)", text):
        if "ESSID" not in block:
            continue  # lo, eth0: "no wireless extensions"
        if re.search(r"Access Point:\s*Not-Associated", block) or "ESSID:off/any" in block:
            return WifiInfo(False)
        info = WifiInfo(True)
        g = re.search(r'ESSID:"(.*?)"', block)
        info.ssid = _real_ssid(g.group(1)) if g else None
        g = re.search(r"Frequency[:=]\s*([\d.]+)\s*GHz", block)
        info.band = _band_from_ghz(float(g.group(1))) if g else None
        g = re.search(r"Bit Rate[:=]\s*([\d.]+)\s*(Mb|Gb)/s", block)
        if g:
            info.rate_mbps = float(g.group(1)) * (1000 if g.group(2) == "Gb" else 1)
        g = re.search(r"Signal level[=:]\s*(-?\d+)\s*dBm", block)
        if g:
            info.signal_dbm = float(g.group(1))
        else:
            g = re.search(r"Signal level[=:]\s*(\d+)/(\d+)", block)
            if g:
                info.signal_dbm = _pct_to_dbm(100.0 * int(g.group(1)) / int(g.group(2)))
        g = re.search(r"Noise level[=:]\s*(-?\d+)\s*dBm", block)
        info.noise_dbm = float(g.group(1)) if g else None
        return info
    return None


def parse_wifi_netsh(text: str) -> Optional[WifiInfo]:
    """`netsh wlan show interfaces` on Windows."""
    state = re.search(r"^\s*State\s*:\s*(.+?)\s*$", text, re.M | re.I)
    if not state:
        return None
    if state.group(1).lower() != "connected":
        return WifiInfo(False)
    info = WifiInfo(True)

    def field_(name: str) -> Optional[str]:
        g = re.search(r"^\s*{}\s*:\s*(.+?)\s*$".format(name), text, re.M | re.I)
        return g.group(1) if g else None

    info.ssid = _real_ssid(field_("SSID"))
    info.phy = field_("Radio type")
    chan = field_("Channel")
    info.channel = int(chan) if chan and chan.isdigit() else None
    band = field_("Band")
    if band:
        info.band = band.replace("GHz", " GHz").replace("  ", " ").strip()
        info.band = "2.4 GHz" if info.band.startswith("2.4") else info.band
    elif info.channel:
        info.band = "2.4 GHz" if info.channel <= 14 else "5 GHz"
    info.rate_mbps = _num((field_(r"Receive rate \(Mbps\)") or "").strip() or None)
    pct = re.search(r"(\d+)\s*%", field_("Signal") or "")
    info.signal_dbm = _pct_to_dbm(float(pct.group(1))) if pct else None
    return info


def parse_wifi(text: str, flavor: str) -> Optional[WifiInfo]:
    """flavor: 'macos' | 'nmcli' | 'iwconfig' | 'netsh'. None = couldn't make sense of it."""
    return {"macos": parse_wifi_macos, "nmcli": parse_wifi_nmcli,
            "iwconfig": parse_wifi_iwconfig, "netsh": parse_wifi_netsh}[flavor](text)


def parse_default_interface(text: str) -> Optional[str]:
    """Which network interface carries the default route? (macOS `interface: en0`, Linux `dev wlan0`)"""
    m = re.search(r"^\s*interface:\s*(\S+)", text, re.M) or re.search(r"\bdev (\S+)", text)
    return m.group(1) if m else None


def parse_hwports_wifi(text: str) -> List[str]:
    """Device names of the Wi-Fi hardware ports from macOS `networksetup -listallhardwareports`."""
    return re.findall(r"Hardware Port:\s*(?:Wi-Fi|AirPort)\s*\nDevice:\s*(\S+)", text)
