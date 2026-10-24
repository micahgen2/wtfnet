"""All the attitude lives here: plain-English explanations of each result.

Keeping the voice separate from the logic means you can rewrite the jokes
(or tone them down) without touching any diagnostic code.
"""

from __future__ import annotations

import random
import re
from typing import Dict, List, Optional, Tuple

_rng = random.Random()


def seed(n: int) -> None:
    """Make the random one-liners repeatable (used by tests)."""
    _rng.seed(n)


def pick(*options: str) -> str:
    return _rng.choice(options)


def _ms(value: Optional[float]) -> str:
    return "?" if value is None else "{:.1f} ms".format(value)


# ---------------------------------------------------------------- generic
def skipped(tool: str, error: Optional[str]) -> str:
    if error == "timeout":
        return "{} took so long I gave up on it. Slow as fuck, and I can't judge what I didn't see.".format(tool)
    return (
        "I couldn't run `{}` ({}), so this step is a blind spot. Install it or run as "
        "a user who's allowed to use it, then try again.".format(tool, error or "unknown error")
    )


def unparsed(tool: str) -> str:
    return (
        "`{}` printed something I can't make sense of. Probably a non-English OS or an "
        "oddball version. Read the raw output above yourself, like an animal.".format(tool)
    )


# ------------------------------------------------------------- interfaces
def _interfaces_v4(usable: List[Tuple[str, str]], link_local: bool) -> str:
    if usable:
        listing = ", ".join("{} on {}".format(ip, name) for name, ip in usable[:3])
        return pick(
            "Found {}. Congrats, your machine has an IP address and is technically attached to a "
            "network. Whether that network gives a shit about you is the next question.".format(listing),
            "{}. You've got an address, so DHCP didn't completely ghost you. The local layer "
            "looks fine.".format(listing),
        )
    if link_local:
        return (
            "The only address I see is 169.254.x.x. That's a self-assigned 'fuck it, I'll make "
            "one up' address your OS invents when DHCP ignores it. Your router isn't handing out "
            "IPs. Reconnect, reboot the router, check the cable."
        )
    return pick(
        "No usable IPv4 address anywhere. You're not on a network, you're a very expensive "
        "paperweight. Check the Wi-Fi toggle, airplane mode, and the damn cable.",
        "Zero IPv4 addresses. Your computer is sitting in the dark with no network and no "
        "dignity. Turn Wi-Fi on, plug something in, or both.",
    )


def interfaces(usable: List[Tuple[str, str]], link_local: bool,
               v6_global: Optional[List[Tuple[str, str]]] = None) -> str:
    """v6_global: None = IPv6 testing is switched off; [] = no global IPv6 address."""
    text = _interfaces_v4(usable, link_local)
    if v6_global is None:
        return text
    if v6_global:
        ip, name = v6_global[0][1], v6_global[0][0]
        return text + " You also have a global IPv6 address ({} on {}), so I'll test IPv6 too.".format(ip, name)
    return text + (
        " No global IPv6 address, so you're IPv4-only. That's normal on plenty of ISPs, "
        "so I'm skipping the IPv6 tests."
    )


# ----------------------------------------------------------------- IPv6
def gateway6_missing() -> str:
    return (
        "You have a global IPv6 address but no IPv6 default route. Your router isn't sending "
        "Router Advertisements (or its IPv6 is half-configured), so IPv6 traffic has nowhere to "
        "go. Apps quietly fall back to IPv4 and you wonder why shit hangs for a few seconds."
    )


def wrong_family(target: str, fam: int) -> str:
    other = 4 if fam == 6 else 6
    return "{} is an IPv{} address, so there's nothing to test over IPv{}. Skipping.".format(target, other, fam)


def ports_noaddr(target: str) -> str:
    return (
        "{} has no IPv6 (AAAA) address, so there's nothing to knock on. Plenty of sites are "
        "still IPv4-only. Not your fault, not a problem.".format(target)
    )


def dns_noaddr(name: str) -> str:
    return (
        "Nobody returned an AAAA (IPv6) record for {}. It's probably just an IPv4-only name, "
        "so I can't judge IPv6 DNS with it. Try --dns-name with a site that has IPv6 "
        "(e.g. google.com).".format(name)
    )


def traceroute6_skipped() -> str:
    return (
        "The IPv6 pings didn't work, so I'm not wasting your time tracing a road that "
        "doesn't exist."
    )


# ---------------------------------------------------------------- gateway
def gateway(ip: Optional[str], stats, status: str, unparsed_cmd: bool = False) -> str:
    if ip is None:
        return (
            "I can't find a default gateway. Without one your computer has no clue where to send "
            "anything that isn't in the building. (On a VPN this can be normal, so don't panic "
            "yet. Check the verdict.)"
        )
    if unparsed_cmd or stats is None:
        return unparsed("ping")
    if stats.received == 0:
        return (
            "{} didn't answer a single ping. Either your router is dead or rebooting, you're not "
            "really connected, or it ignores ping (some do, the assholes). The verdict will "
            "cross-check against the internet tests.".format(ip)
        )
    if stats.loss_pct > 0:
        return (
            "Lost {:g}% of pings to your own router, which is ten feet away. That's flaky-ass "
            "Wi-Fi bullshit. Move closer, change channels, or sacrifice something to the "
            "router gods.".format(stats.loss_pct)
        )
    if status == "warn":
        return (
            "{} answers, but {} to a box that's practically in the room? That's trash. "
            "Wi-Fi interference, a congested channel, or the router is having a stroke. "
            "Try Ethernet.".format(ip, _ms(stats.avg_ms))
        )
    return pick(
        "Gateway {} answered {}/{} pings in {}. Your router is alive and not being a dick. Local "
        "network: fine.".format(ip, stats.received, stats.sent, _ms(stats.avg_ms)),
        "{} replied every time, averaging {}. The router's doing its one job. Good "
        "router.".format(ip, _ms(stats.avg_ms)),
    )


# --------------------------------------------------------------- internet
def internet(rows: List[Tuple[str, str, object]], status: str) -> str:
    """rows: (host, label, PingStats|None)."""
    stats = [s for _, _, s in rows if s is not None]
    if not stats:
        return unparsed("ping")
    replied = [(h, l, s) for h, l, s in rows if s is not None and s.received > 0]
    if not replied:
        return (
            "Neither Cloudflare nor Google answered. Your packets leave the house and vanish into "
            "the void. If the gateway looked fine, that points at your ISP. (Or a firewall that "
            "blocks ping. The DNS and TCP tests will help cross-check.)"
        )
    if len(replied) < len(rows):
        dead = [l for h, l, s in rows if s is None or s.received == 0]
        return (
            "{} didn't answer but the other did, so the internet works. The silent one is "
            "probably blocking ping or having a bad day. Not your problem.".format(" and ".join(dead))
        )
    lossy = [s for _, _, s in replied if s.loss_pct > 0]
    if lossy:
        return (
            "Both answered, but with packet loss (up to {:g}%). The connection works, it's just "
            "flaky as hell. If the gateway looked clean too, blame your ISP "
            "or the line.".format(max(s.loss_pct for s in lossy))
        )
    avgs = " / ".join(_ms(s.avg_ms) for _, _, s in replied)
    if status == "warn":
        return "Both answered with 0% loss but it's slow as molasses ({}). Your ISP is giving you dial-up energy.".format(avgs)
    return pick(
        "Both answered, 0% loss ({}). The internet exists and you're on it. Enjoy.".format(avgs),
        "Cloudflare and Google both replied clean ({}). Your connection to the outside world "
        "is working. Quit staring at me.".format(avgs),
    )


# -------------------------------------------------------------------- DNS
def dns(rows: List[dict], status: str) -> str:
    """rows[0] is the system resolver, the rest are public ones."""
    system, publics = rows[0], rows[1:]
    timings = ", ".join(
        "{} {}".format(r["label"], "{:.0f} ms".format(r["ms"]) if r["ok"] else "FAILED")
        for r in rows
        if r["ok"] is not None
    )
    if system["ok"] is False:
        if any(r["ok"] for r in publics):
            return (
                "Your system resolver shit the bed ({}) while Cloudflare/Google answered fine. It's "
                "DNS. It's always DNS. Switch your DNS servers to 1.1.1.1 / 8.8.8.8 or reboot "
                "the router.".format(system["error"] or "failed")
            )
        return (
            "Not one resolver could look up that name ({}). Either you've got no internet, or "
            "something is blocking DNS entirely. Check the ping results above before blaming "
            "DNS.".format(timings)
        )
    if status == "warn":
        return (
            "DNS works but your system resolver is slow as fuck ({}). Every website you open pays "
            "that tax. Try 1.1.1.1 or 8.8.8.8.".format(timings)
        )
    if publics and all(r["ok"] is False for r in publics):
        return (
            "Your resolver works ({}), but I can't reach the public ones. Some networks hijack "
            "or block outside DNS. Harmless unless you were trying to use them.".format(timings)
        )
    return pick(
        "All resolvers answered ({}). DNS is fine, so for once it's NOT DNS.".format(timings),
        "Name lookups work everywhere ({}). Quit blaming DNS, it's innocent this time.".format(timings),
    )


# ------------------------------------------------------------- traceroute
def traceroute(trace, target: str, status: str) -> str:
    if trace is None or not trace.hops:
        return (
            "I couldn't read any hops out of that. The target name may not resolve, or the "
            "command errored. The raw output above has the real story."
        )
    n = len(trace.hops)
    if trace.reached:
        return pick(
            "Reached {} in {} hops. Every router between you and it did its job. The `* * *` rows "
            "are just routers that don't answer traceroute. Rude, but harmless.".format(target, n),
            "Made it to {} in {} hops, no drama. Ignore any `* * *` lines: those routers just "
            "refuse to talk to strangers.".format(target, n),
        )
    responding = trace.responding
    if not responding:
        return (
            "Not a single hop answered, not even your own router. Either you're offline or "
            "something upstream is eating every probe."
        )
    last = responding[-1]
    return (
        "The trail goes cold after hop {} ({}). Plenty of servers firewall traceroute probes, so "
        "that alone proves nothing. But if the other tests are also red, this is roughly where "
        "the path breaks.".format(last.n, last.ip)
    )


# ------------------------------------------------------------------ ports
def ports(results: List[object], target: str, status: str) -> str:
    opened = [r.port for r in results if r.state == "open"]
    closed = [r.port for r in results if r.state == "closed"]
    filtered = [r.port for r in results if r.state == "filtered"]
    errors = [r for r in results if r.state == "error"]

    if errors and not opened and not closed and not filtered:
        return (
            "I couldn't even try. {} ({}). Fix the name or your network "
            "first.".format(errors[0].detail or "connection error", target)
        )
    if status == "ok":
        return pick(
            "Every port answered ({}). {} is up and listening. Whatever's broken, it isn't "
            "this.".format(", ".join(map(str, opened)), target),
            "All ports open ({}). {} is alive and accepting connections like a "
            "champ.".format(", ".join(map(str, opened)), target),
        )
    parts = []
    if opened:
        parts.append("open: {}".format(", ".join(map(str, opened))))
    if closed:
        parts.append(
            "closed: {} (the host answered 'nope', so it's alive but nothing's listening there)".format(
                ", ".join(map(str, closed))
            )
        )
    if filtered:
        parts.append(
            "no response: {} (a firewall is silently eating your packets, or the host is "
            "dead)".format(", ".join(map(str, filtered)))
        )
    prefix = "Mixed bag on {}: ".format(target) if opened else "Nothing's open on {}: ".format(target)
    tail = "" if opened else " If the rest of your network is fine, the problem is on their end."
    return prefix + "; ".join(parts) + "." + tail


# ------------------------------------------------------------------ Wi-Fi
_WIFI_ISSUES = {
    "weak_signal": "a signal of {dbm:.0f} dBm is weak (you want stronger than -67)",
    "low_snr": "your signal is only {snr:.0f} dB above the background noise (you want 25+)",
    "slow_link": "the negotiated link speed is just {rate:.0f} Mbps",
}


def wifi(info, issues: List[str], status: str) -> str:
    if info is None:
        return unparsed("the Wi-Fi tool")
    if not info.connected:
        return (
            "The OS says Wi-Fi isn't connected, yet your traffic is going over it. Either I "
            "can't read this OS's output properly, or something odd is happening."
        )
    where = " to {}".format(info.ssid) if info.ssid else ""
    bits = []
    if info.band:
        bits.append(info.band + (", channel {}".format(info.channel) if info.channel else ""))
    if info.signal_dbm is not None:
        bits.append("signal {:.0f} dBm".format(info.signal_dbm))
    if info.snr_db is not None:
        bits.append("{:.0f} dB above the noise".format(info.snr_db))
    if info.rate_mbps is not None:
        bits.append("link speed {:.0f} Mbps".format(info.rate_mbps))
    summary = "Connected{} ({}).".format(where, ", ".join(bits)) if bits else "Connected{}.".format(where)
    if not issues:
        return summary + pick(
            " That's a healthy link, so if things are slow, it isn't your radio.",
            " Solid. Your Wi-Fi is doing its job for once.",
        )
    reasons = "; ".join(_WIFI_ISSUES[i].format(
        dbm=info.signal_dbm or 0, snr=info.snr_db or 0, rate=info.rate_mbps or 0) for i in issues)
    text = "{} Your Wi-Fi link is a mess: {}. Move closer to the router, get clear of walls and " \
           "microwaves, or just plug in a cable.".format(summary, reasons)
    if info.band == "2.4 GHz":
        text += " You're also on 2.4 GHz, the slow, crowded band. Use 5 or 6 GHz if your router offers it."
    return text


def wifi_note(info, issues: List[str]) -> str:
    """One sentence appended to the GATEWAY verdict when the Wi-Fi radio itself is the culprit."""
    reasons = "; ".join(_WIFI_ISSUES[i].format(
        dbm=info.signal_dbm or 0, snr=info.snr_db or 0, rate=info.rate_mbps or 0) for i in issues)
    return "And the cause is visible: {}.".format(reasons)


# ------------------------------------------------------------ HTTPS / TLS
def _slowest(r) -> str:
    phases = [("DNS", r.dns_ms), ("TCP connect", r.connect_ms), ("TLS handshake", r.tls_ms),
              ("waiting for the server", r.ttfb_ms)]
    phases = [(n, v) for n, v in phases if v is not None]
    return max(phases, key=lambda p: p[1])[0] if phases else "unknown"


def http(r, status: str) -> str:
    host = r.url.split("/")[2]
    if r.error == "dns":
        return "Couldn't even look up {}. {}. Check the spelling, or it's DNS (see above).".format(host, r.detail)
    if r.error == "tls_verify":
        return (
            "The TLS certificate was rejected: {}. Either the site's cert is busted, something "
            "(a captive portal, antivirus, corporate proxy) is intercepting HTTPS, or your "
            "computer's clock is wrong. Check the date and time first. It's embarrassing how "
            "often that's it.".format(r.detail)
        )
    if r.error == "tls":
        return "The TLS handshake failed ({}). Your machine and the server couldn't agree how to encrypt.".format(r.detail)
    if r.error:
        return "TCP might connect, but a real HTTPS request didn't work: {}.".format(r.detail)
    base = "Got {} in {:.0f} ms (slowest part: {}).".format(r.status, r.total_ms or 0, _slowest(r))
    if r.status >= 500:
        return "{} The server is up but throwing errors. That's their server shitting itself, not your network.".format(base)
    if r.cert_days_left is not None and r.cert_days_left < 14:
        return ("{} But the certificate expires in {:.0f} days. Tell whoever runs it, or this "
                "becomes a very sudden outage.".format(base, r.cert_days_left))
    if status == "warn":
        return "{} That's slow. Look at the slowest phase and check it against the DNS and ping results.".format(base)
    note = ""
    if r.status >= 400:
        note = " (A {} just means the server dislikes a bare GET. It's alive, which is what I care about.)".format(r.status)
    return base + " Certificate valid for {:.0f} more days. The site works end to end, not just the port.{}".format(
        r.cert_days_left if r.cert_days_left is not None else 0, note)


def captive(r, status: str) -> str:
    if r.error:
        return ("I couldn't run the captive portal check ({}). Can't tell either way. If the "
                "internet is down, that's why.".format(r.detail))
    if r.status == 204 and not r.body.strip():
        return ("Got the empty 204 response Google's connectivity check should return, so nobody "
                "is tampering with your web traffic. No captive portal.")
    where = " (redirecting to {})".format(r.headers["location"]) if r.headers.get("location") else ""
    if status == "fail":
        return (
            "Expected a blank 204 and got {}{} instead. Something between you and the internet "
            "is answering web requests with its own page. That's a captive portal: the login "
            "screen on hotel, airport and cafe Wi-Fi.".format(r.status, where)
        )
    return "Got an unexpected {} from the connectivity check. Odd, but it doesn't look like a login page.".format(r.status)


# ------------------------------------------------------------ extra hosts
def extra_pings(rows: List[Tuple[str, object]], status: str) -> str:
    """rows: (host, PingStats|None)."""
    up = [h for h, s in rows if s is not None and s.received > 0]
    down = [h for h, s in rows if s is None or s.received == 0]
    if not down:
        return "Every host you asked about answered: {}. They're alive and not ignoring you.".format(", ".join(up))
    if not up:
        return ("None of your extra hosts answered ({}). If the rest of the network is fine, those "
                "machines are down, asleep, firewalled, or on another network.".format(", ".join(down)))
    return "{} answered, but {} didn't. The silent ones are down, asleep, or ignoring ping.".format(
        ", ".join(up), ", ".join(down))


# ---------------------------------------------------------------- verdict
# layer -> status -> (headline, detail, fixes)
_V: Dict[Tuple[str, str], Tuple[str, str, List[str]]] = {
    ("none", "ok"): (
        "Everything's fine. Go outside.",
        "I ran the whole battery and found nothing wrong. If something still feels broken, it's "
        "probably the specific site or app, or an intermittent problem. Try --watch to catch it "
        "in the act.",
        [],
    ),
    ("none", "warn"): (
        "I can't tell, because half my tools didn't run.",
        "Most steps were skipped, so I'm guessing in the dark and I refuse to guess. See which "
        "commands were missing above.",
        ["Install the missing tools (ping, traceroute, nslookup) and rerun."],
    ),
    ("local", "fail"): (
        "LOCAL: your own machine can't get on the network.",
        "You don't have a usable IP address, so this is between you and your computer. Nothing "
        "past your front door was even tested fairly.",
        [
            "Make sure Wi-Fi is on, airplane mode is off, and the Ethernet cable is actually plugged in.",
            "Turn the network adapter off and on again (or reboot the damn computer).",
            "Seeing a 169.254.x.x address? DHCP isn't answering. Reboot the router.",
        ],
    ),
    ("gateway", "fail"): (
        "GATEWAY: your router (or your connection to it) is the problem.",
        "You have an IP address, but your router isn't answering or you have no default route. "
        "Everything past it is unreachable.",
        [
            "Power-cycle the router: unplug it for 30 seconds, plug it back in.",
            "Move closer, or try Ethernet to rule out Wi-Fi.",
            "On a VPN? Disconnect it and rerun.",
        ],
    ),
    ("gateway", "warn"): (
        "GATEWAY (degraded): your local link is flaky.",
        "The internet works, but the hop to your own router is lossy or slow. That's almost "
        "always Wi-Fi: distance, interference, or a congested channel.",
        [
            "Try Ethernet. If the problem vanishes, it was Wi-Fi.",
            "Switch to the 5 GHz band or change the router's channel.",
            "Move closer and keep it away from microwaves and your neighbours' routers.",
        ],
    ),
    ("isp", "fail"): (
        "ISP: the problem is upstream of your router.",
        "Your router is fine, but nothing beyond it replies. That means the modem, the line, or "
        "your ISP.",
        [
            "Reboot the modem first, wait a few minutes, then the router.",
            "Check your ISP's outage page from your phone on mobile data.",
            "Still dead after 15 minutes? Call them and say: 'my router works, I can't reach 1.1.1.1'.",
        ],
    ),
    ("isp", "warn"): (
        "ISP (degraded): packet loss or high latency out on the internet.",
        "Your local network is clean, but traffic to the wider internet is lossy or slow. That "
        "points at the line, the modem, or your ISP having a bad day.",
        [
            "Run `wtfnet --watch 60 --html-report` for an hour to build evidence.",
            "Reboot the modem. Check for line noise or loose coax/phone cables.",
            "Send your ISP the report. Evidence beats 'my internet is slow'.",
        ],
    ),
    ("dns", "fail"): (
        "DNS: name lookups are broken, everything else works.",
        "You can reach the internet by IP address, but your system's DNS resolver can't turn "
        "names into addresses. That's the whole problem.",
        [
            "Set your DNS servers to 1.1.1.1 and 8.8.8.8 in your network settings.",
            "Flush the DNS cache: `ipconfig /flushdns` (Windows), `sudo dscacheutil -flushcache` "
            "(macOS), `resolvectl flush-caches` (Linux).",
            "Reboot the router. Its DNS forwarder may be hung.",
        ],
    ),
    ("dns", "warn"): (
        "DNS (slow): your resolver is sluggish.",
        "Everything works, but your default DNS resolver is much slower than the public ones. "
        "Every website you open pays that delay.",
        [
            "Switch your DNS servers to 1.1.1.1 / 8.8.8.8.",
            "Reboot the router if you're using its built-in DNS.",
        ],
    ),
    ("portal", "fail"): (
        "CAPTIVE PORTAL: this network wants you to log in first.",
        "Something between you and the internet is intercepting plain web traffic and answering "
        "with its own page. That's a captive portal, the login screen on hotel, airport and cafe "
        "Wi-Fi. Until you click through it, DNS and web requests can look broken even though pings work.",
        [
            "Open a browser and go to http://neverssl.com. It never uses HTTPS, so the login page can intercept it.",
            "Accept the terms or sign in, then rerun wtfnet.",
            "No login page appears? Disconnect and reconnect to the Wi-Fi to trigger it again.",
        ],
    ),
    ("remote", "fail"): (
        "REMOTE: it's them, not you.",
        "Your network and DNS are fine, but {target} is broken from here ({notes}). The server "
        "is down, firewalled, or you've got the wrong host or port.",
        [
            "Check the service's status page, or try from your phone on mobile data.",
            "Double-check --target and --ports.",
            "Wait. Nothing you do locally will fix someone else's server.",
        ],
    ),
    ("remote", "warn"): (
        "REMOTE (partial): {target} isn't fully healthy.",
        "Your network is fine, but {target} has problems: {notes}. That might be normal or it "
        "might be the server's problem.",
        ["Make sure every port you listed is actually supposed to be open."],
    ),
    ("hosts", "warn"): (
        "YOUR HOSTS: {hosts} not answering.",
        "The internet is fine, but the extra machines you asked me to ping aren't all reachable. "
        "They're down, asleep, firewalled, or on a different network.",
        [
            "Check the machine is powered on and on the same network or VPN.",
            "Some devices ignore ping on purpose. Try reaching them the way you normally would.",
        ],
    ),
    ("ipv6", "warn"): (
        "IPv6 (broken): IPv4 works fine, IPv6 doesn't.",
        "Everything works over IPv4, but IPv6 traffic isn't getting through. Apps usually fall "
        "back to IPv4 after an annoying delay, which is why some sites hang for a few seconds "
        "before loading. This is a classic router or ISP IPv6 misconfiguration.",
        [
            "Reboot the router and modem so they renew IPv6 settings (Router Advertisements).",
            "Check the router's IPv6 setting. Some have a broken 'IPv6 passthrough' or firewall.",
            "If your ISP doesn't really provide IPv6, turn IPv6 off on the router or adapter.",
            "Rerun with --no-ipv6 to confirm everything else is clean.",
        ],
    ),
}


def verdict(layer: str, status: str, target: str, notes: str = "",
            hosts: str = "") -> Tuple[str, str, List[str]]:
    """notes: what's wrong with the target (REMOTE); hosts: the unreachable extra hosts (YOUR HOSTS)."""
    headline, detail, fixes = _V.get((layer, status)) or _V[("none", "warn")]
    fmt = dict(target=target, notes=notes or "the ports tested aren't answering", hosts=hosts)
    return headline.format(**fmt), detail.format(**fmt), list(fixes)


# ------------------------------------------------------------ safe for work
# Ordered (pattern, replacement) pairs. Specific phrases first so they read naturally,
# generic word swaps last. A test checks that NO string in this file survives clean().
_CLEAN = [
    (r"slow as (?:fuck|shit)", "very slow"),
    (r"flaky-ass", "flaky"),
    (r"flaky as hell", "very flaky"),
    (r"shit the bed", "fell over"),
    (r"shitting itself", "falling over"),
    (r"a shit\b", "a hoot"),
    (r"fuck it", "forget it"),
    (r"bullshit", "nonsense"),
    (r"assholes?", "jerks"),
    (r"\bdick\b", "jerk"),
    (r"\bdamn\b", "darn"),
    (r"\bfucking\b", "freaking"),
    (r"\bfuck(?:ed)?\b", "heck"),
    (r"\bshit\b", "stuff"),
    (r"\bhell\b", "heck"),
    (r"\bass\b", "butt"),
]


def _match_case(original: str, replacement: str) -> str:
    return replacement[:1].upper() + replacement[1:] if original[:1].isupper() else replacement


def clean(text: str) -> str:
    """Swap the profanity for milder words (--clean)."""
    for pattern, replacement in _CLEAN:
        text = re.sub(pattern, lambda m, r=replacement: _match_case(m.group(0), r), text, flags=re.I)
    return text
