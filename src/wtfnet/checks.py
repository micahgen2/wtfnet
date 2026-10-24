"""The diagnostic steps. Each check_* function returns one StepResult.

Everything that touches the outside world (running commands, opening
sockets) comes in through `Context`, so tests can swap in fakes.

Most checks take a `fam` argument (4 or 6) so IPv4 and IPv6 share one
implementation; they differ only in which command, hosts and parser they use.
"""

from __future__ import annotations

import shutil
import socket
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from . import parsers, sass
from .models import FAIL, OK, SKIP, WARN, Exec, StepResult
from .platform_cmds import (
    PING_COUNT,
    gateway6_cmd,
    gateway_cmd,
    interfaces_cmd,
    nslookup_cmd,
    ping_cmd,
    traceroute_cmd,
)
from .runner import CommandResult, format_command, run_command

# Tunables: what counts as "slow" or "bad". Change these to taste.
GATEWAY_LATENCY_WARN_MS = 30
INTERNET_LATENCY_WARN_MS = 150
DNS_SLOW_MS = 250
DNS_SLOW_RATIO = 2.5  # system resolver must also be this many times slower than the best public one
TCP_TIMEOUT = 3.0

INTERNET_HOSTS = {
    4: [("1.1.1.1", "Cloudflare"), ("8.8.8.8", "Google")],
    6: [("2606:4700:4700::1111", "Cloudflare"), ("2001:4860:4860::8888", "Google")],
}
DNS_SERVERS = {
    4: [(None, "system"), ("1.1.1.1", "Cloudflare"), ("8.8.8.8", "Google")],
    6: [(None, "system"), ("2606:4700:4700::1111", "Cloudflare"), ("2001:4860:4860::8888", "Google")],
}


# ------------------------------------------------------------ TCP probing
@dataclass
class TcpResult:
    port: int
    state: str  # open | closed | filtered | error | noaddr
    ms: Optional[float] = None
    detail: str = ""


def tcp_probe(host: str, port: int, timeout: float = TCP_TIMEOUT, family: int = 4) -> TcpResult:
    """Try a real TCP connection over one IP version, like `nc -zv -4/-6 host port`.

    open     = the three-way handshake completed.
    closed   = the host answered "nobody's listening" (connection refused).
    filtered = total silence; a firewall dropped it or the host is down.
    noaddr   = (IPv6 only) the name has no AAAA record, so there's nothing to try.
    """
    af = socket.AF_INET6 if family == 6 else socket.AF_INET
    try:
        # Ask only for addresses of the family we're testing, and use the first.
        fam, kind, proto, _, addr = socket.getaddrinfo(host, port, af, socket.SOCK_STREAM)[0]
    except socket.gaierror as exc:
        if family == 6:
            return TcpResult(port, "noaddr", None, "{} has no IPv6 (AAAA) address".format(host))
        return TcpResult(port, "error", None, "can't resolve {} ({})".format(host, exc))

    start = time.monotonic()
    sock = socket.socket(fam, kind, proto)
    try:
        sock.settimeout(timeout)
        sock.connect(addr)
        return TcpResult(port, "open", (time.monotonic() - start) * 1000, "via " + addr[0])
    except socket.timeout:  # must come before OSError, which it is a child of
        return TcpResult(port, "filtered", None, "timed out after {:g}s".format(timeout))
    except ConnectionRefusedError:
        return TcpResult(port, "closed", (time.monotonic() - start) * 1000, "connection refused")
    except OSError as exc:  # e.g. "Network is unreachable" when IPv6 has no route
        return TcpResult(port, "error", None, str(exc))
    finally:
        sock.close()


def system_resolve(name: str, family: int = 4) -> List[str]:
    """Fallback DNS lookup through the OS resolver, for when nslookup is missing."""
    af = socket.AF_INET6 if family == 6 else socket.AF_INET
    infos = socket.getaddrinfo(name, None, af)
    return sorted({info[4][0] for info in infos})


# ----------------------------------------------------------------- context
@dataclass
class Context:
    system: str
    target: str
    ports: List[int]
    dns_name: str = "example.com"
    ipv6: bool = True  # False = never run the IPv6 steps (--no-ipv6)
    run: Callable[..., CommandResult] = run_command
    tcp_connect: Callable[..., TcpResult] = tcp_probe
    which: Callable[[str], Optional[str]] = shutil.which
    resolve: Callable[..., List[str]] = system_resolve
    # Scratch space shared by the steps of ONE battery run (cleared before each run).
    state: Dict[str, object] = field(default_factory=dict)


def has_ipv6(ctx: Context) -> bool:
    """Should the IPv6 steps run? Only if enabled AND we hold a global IPv6 address."""
    return bool(ctx.ipv6 and ctx.state.get("v6_global"))


def _record(res: CommandResult, system: str) -> Exec:
    text = res.output
    if res.error == "timeout":
        text = (text + "\n" if text else "") + "[wtfnet: command timed out and was stopped]"
    return Exec(format_command(res.argv, system), text, res.elapsed)


def _classify_ping(stats: parsers.PingStats, latency_warn_ms: float) -> str:
    if stats.received == 0:
        return FAIL
    if stats.loss_pct >= 50:
        return FAIL
    if stats.loss_pct > 0:
        return WARN
    if stats.avg_ms is not None and stats.avg_ms > latency_warn_ms:
        return WARN
    return OK


def _ping_host(ctx: Context, host: str, fam: int = 4):
    """Returns (Exec, PingStats|None, error|None). error: not_found/os_error/unparsed."""
    res = ctx.run(ping_cmd(host, ctx.system, family=fam), 25)
    ex = _record(res, ctx.system)
    if res.error in ("not_found", "os_error"):
        return ex, None, res.error
    stats = parsers.parse_ping(res.output, ctx.system, PING_COUNT)
    if stats is None and res.error == "timeout":
        stats = parsers.PingStats(PING_COUNT, 0)  # no output before the timeout = no replies
    if stats is None:
        return ex, None, "unparsed"
    return ex, stats, None


# Naming helpers so v4 and v6 steps can share code.
def _key(base: str, fam: int) -> str:
    return base + ("6" if fam == 6 else "")


def _title(text: str, fam: int) -> str:
    if fam != 6:
        return text
    # Lowercase the first letter ("Gateway ping" -> "IPv6 gateway ping") but leave acronyms alone ("TCP").
    first = text[0].lower() if text[1:2].islower() else text[0]
    return "IPv6 " + first + text[1:]


def _layer(v4_layer: str, fam: int) -> str:
    return "ipv6" if fam == 6 else v4_layer


def _wrong_family_target(ctx: Context, fam: int) -> bool:
    """True if --target is an IP literal of the other IP version."""
    tf = parsers.ip_family(ctx.target)
    return tf is not None and tf != fam


# ----------------------------------------------------------------- steps
def check_interfaces(ctx: Context) -> StepResult:
    title = "Local interface info"
    argv = interfaces_cmd(ctx.system, ctx.which)
    res = ctx.run(argv, 15)
    ex = _record(res, ctx.system)
    if res.error:
        return StepResult("interfaces", title, "local", SKIP, sass.skipped(argv[0], res.error), [ex])

    flavor = {"ip": "ip", "ipconfig": "ipconfig"}.get(argv[0], "ifconfig")
    ifaces = parsers.parse_interfaces(res.output, flavor)
    usable = [(i.name, i.ip) for i in ifaces if not i.is_link_local]
    link_local = any(i.is_link_local for i in ifaces)
    v6_global = [(i.name, i.ip) for i in parsers.parse_interfaces6(res.output, flavor) if i.is_global]
    ctx.state["v6_global"] = v6_global  # tells the runner whether to add the IPv6 steps
    status = OK if usable else FAIL
    return StepResult(
        "interfaces", title, "local", status,
        sass.interfaces(usable, link_local, v6_global if ctx.ipv6 else None), [ex],
        {"usable": usable, "link_local": link_local, "v6_global": v6_global},
    )


def check_gateway(ctx: Context, fam: int = 4) -> StepResult:
    key, title, layer = _key("gateway", fam), _title("Gateway ping", fam), _layer("gateway", fam)
    argv = (gateway6_cmd if fam == 6 else gateway_cmd)(ctx.system, ctx.which)
    res = ctx.run(argv, 15)
    execs = [_record(res, ctx.system)]
    if res.error:
        return StepResult(key, title, layer, SKIP, sass.skipped(argv[0], res.error), execs)

    gw = (parsers.parse_default_route6 if fam == 6 else parsers.parse_gateway)(res.output)
    if gw is None:
        text = sass.gateway6_missing() if fam == 6 else sass.gateway(None, None, FAIL)
        return StepResult(key, title, layer, FAIL, text, execs, {"gateway": None, "stats": None})

    ex, stats, err = _ping_host(ctx, gw, fam)
    execs.append(ex)
    if err in ("not_found", "os_error"):
        return StepResult(key, title, layer, SKIP, sass.skipped("ping", err), execs, {"gateway": gw})
    if stats is None:
        return StepResult(key, title, layer, WARN, sass.gateway(gw, None, WARN, True), execs,
                          {"gateway": gw, "stats": None})
    status = _classify_ping(stats, GATEWAY_LATENCY_WARN_MS)
    return StepResult(key, title, layer, status, sass.gateway(gw, stats, status), execs,
                      {"gateway": gw, "stats": stats})


def check_internet(ctx: Context, fam: int = 4) -> StepResult:
    key, layer = _key("internet", fam), _layer("isp", fam)
    hosts = INTERNET_HOSTS[fam]
    title = ("IPv6 internet ping (Cloudflare and Google)" if fam == 6
             else "Internet ping (1.1.1.1 and 8.8.8.8)")
    execs: List[Exec] = []
    rows: List[Tuple[str, str, Optional[parsers.PingStats]]] = []
    statuses: List[str] = []
    missing = None
    for host, label in hosts:
        ex, stats, err = _ping_host(ctx, host, fam)
        execs.append(ex)
        if err in ("not_found", "os_error"):
            missing = err
        rows.append((host, label, stats))
        if stats is not None:
            statuses.append(_classify_ping(stats, INTERNET_LATENCY_WARN_MS))

    if missing:
        return StepResult(key, title, layer, SKIP, sass.skipped("ping", missing), execs, {"any_reply": False})
    any_reply = any(s is not None and s.received > 0 for _, _, s in rows)
    if fam == 6:
        ctx.state["v6_alive"] = any_reply  # lets the slow IPv6 traceroute skip itself
    if not statuses:
        status = WARN
    elif all(s == OK for s in statuses) and len(statuses) == len(rows):
        status = OK
    elif not any_reply:
        status = FAIL
    else:
        status = WARN
    return StepResult(key, title, layer, status, sass.internet(rows, status), execs,
                      {"any_reply": any_reply, "stats": {h: s for h, _, s in rows}})


def _lookup(ctx: Context, server: Optional[str], label: str, fam: int) -> Tuple[Exec, dict]:
    argv = nslookup_cmd(ctx.dns_name, server, "AAAA" if fam == 6 else None)
    res = ctx.run(argv, 15)
    ex = _record(res, ctx.system)
    row = {"label": label, "server": server, "ok": None, "ms": None, "error": None}

    if res.error == "not_found":
        if server is not None:
            return ex, row  # can't query a specific server without nslookup: skipped
        # System resolver fallback: ask Python's socket library to do it.
        start = time.monotonic()
        display = 'python: socket.getaddrinfo("{}", None, {})'.format(
            ctx.dns_name, "AF_INET6" if fam == 6 else "AF_INET")
        try:
            answers = ctx.resolve(ctx.dns_name, fam)
            row.update(ok=True, ms=(time.monotonic() - start) * 1000)
            return Exec(display, ", ".join(answers), time.monotonic() - start), row
        except OSError as exc:
            row.update(ok=False, ms=(time.monotonic() - start) * 1000, error="nxdomain")
            return Exec(display, "lookup failed: {}".format(exc), time.monotonic() - start), row
    if res.error == "os_error":
        return ex, row

    parsed = parsers.parse_nslookup(res.output, fam)
    if parsed.error == "noanswer" and fam == 6:
        return ex, row  # the server answered but the name has no AAAA record: not a failure
    row.update(ok=parsed.ok, ms=res.elapsed * 1000, error=parsed.error)
    return ex, row


def check_dns(ctx: Context, fam: int = 4) -> StepResult:
    key, layer = _key("dns", fam), _layer("dns", fam)
    title = "IPv6 DNS (AAAA) resolution timing" if fam == 6 else "DNS resolution timing"
    execs: List[Exec] = []
    rows: List[dict] = []
    for server, label in DNS_SERVERS[fam]:
        ex, row = _lookup(ctx, server, label, fam)
        execs.append(ex)
        rows.append(row)

    if all(r["ok"] is None for r in rows):
        tool_missing = any(e.output.startswith("command not found") for e in execs)
        if fam == 6 and not tool_missing:
            text = sass.dns_noaddr(ctx.dns_name)  # servers answered, but no AAAA record exists
        else:
            text = sass.skipped("nslookup", "not_found")
        return StepResult(key, title, layer, SKIP, text, execs,
                          {"system_ok": None, "public_ok": False, "rows": rows})

    system, publics = rows[0], rows[1:]
    public_ok = any(r["ok"] for r in publics)
    status = OK
    if system["ok"] is False:
        status = FAIL
    else:
        fast = [r["ms"] for r in publics if r["ok"]]
        if (system["ok"] and fast and system["ms"] > DNS_SLOW_MS
                and system["ms"] > DNS_SLOW_RATIO * min(fast)):
            status = WARN
    return StepResult(key, title, layer, status, sass.dns(rows, status), execs,
                      {"system_ok": system["ok"], "public_ok": public_ok, "rows": rows})


def check_traceroute(ctx: Context, fam: int = 4) -> StepResult:
    key, layer = _key("traceroute", fam), _layer("remote", fam)
    title = _title("Traceroute to {}".format(ctx.target), fam)
    if _wrong_family_target(ctx, fam):
        return StepResult(key, title, layer, SKIP, sass.wrong_family(ctx.target, fam))
    if fam == 6 and ctx.state.get("v6_alive") is False:
        return StepResult(key, title, layer, SKIP, sass.traceroute6_skipped())

    argv = traceroute_cmd(ctx.target, ctx.system, family=fam)
    res = ctx.run(argv, 90)
    ex = _record(res, ctx.system)
    if res.error in ("not_found", "os_error"):
        return StepResult(key, title, layer, SKIP, sass.skipped(argv[0], res.error), [ex])

    trace = parsers.parse_traceroute(res.output, ctx.target)
    if trace.reached:
        status = OK
    elif trace.responding:
        status = WARN
    elif trace.hops:
        status = FAIL
    else:
        status = WARN
    return StepResult(
        key, title, layer, status, sass.traceroute(trace, ctx.target, status), [ex],
        {"reached": trace.reached, "hops": len(trace.hops), "responding": len(trace.responding)},
    )


def check_ports(ctx: Context, fam: int = 4) -> StepResult:
    key, layer = _key("ports", fam), _layer("remote", fam)
    title = _title("TCP port checks on {}".format(ctx.target), fam)
    if _wrong_family_target(ctx, fam):
        return StepResult(key, title, layer, SKIP, sass.wrong_family(ctx.target, fam))

    execs: List[Exec] = []
    results: List[TcpResult] = []
    for port in ctx.ports:
        start = time.monotonic()
        r = ctx.tcp_connect(ctx.target, port, TCP_TIMEOUT, fam)
        results.append(r)
        label = r.state.upper()
        if r.ms is not None:
            label += " in {:.1f} ms".format(r.ms)
        if r.detail:
            label += " ({})".format(r.detail)
        display = 'python: connect(AF_INET{}, ("{}", {}), timeout={:g})'.format(
            "6" if fam == 6 else "", ctx.target, port, TCP_TIMEOUT)
        execs.append(Exec(display, "{}/tcp {}".format(port, label), time.monotonic() - start))

    if fam == 6 and results and all(r.state == "noaddr" for r in results):
        return StepResult(key, title, layer, SKIP, sass.ports_noaddr(ctx.target), execs,
                          {"open_count": 0, "reachable_count": 0, "states": {}, "dns_error": False})

    open_n = sum(r.state == "open" for r in results)
    # "closed" still proves the host is reachable: it sent back a refusal.
    reachable = sum(r.state in ("open", "closed") for r in results)
    if open_n == len(results):
        status = OK
    elif open_n == 0:
        status = FAIL
    else:
        status = WARN
    return StepResult(
        key, title, layer, status, sass.ports(results, ctx.target, status), execs,
        {"open_count": open_n, "reachable_count": reachable,
         "states": {r.port: r.state for r in results},
         "dns_error": any(r.state == "error" and "resolve" in r.detail for r in results)},
    )


@dataclass
class Step:
    key: str
    label: str  # shown on the spinner while it runs
    fn: Callable[[Context], StepResult]


STEPS = [
    Step("interfaces", "Checking your network interfaces", check_interfaces),
    Step("gateway", "Pinging your gateway", check_gateway),
    Step("internet", "Pinging the internet", check_internet),
    Step("dns", "Timing DNS resolvers", check_dns),
    Step("traceroute", "Tracing the route (this one's slow, be patient)", check_traceroute),
    Step("ports", "Knocking on TCP ports", check_ports),
]

# Added to the end of the run only when the machine has a global IPv6 address.
STEPS6 = [
    Step("gateway6", "Pinging your IPv6 gateway", lambda ctx: check_gateway(ctx, 6)),
    Step("internet6", "Pinging the internet over IPv6", lambda ctx: check_internet(ctx, 6)),
    Step("dns6", "Timing IPv6 (AAAA) lookups", lambda ctx: check_dns(ctx, 6)),
    Step("traceroute6", "Tracing the IPv6 route", lambda ctx: check_traceroute(ctx, 6)),
    Step("ports6", "Knocking on TCP ports over IPv6", lambda ctx: check_ports(ctx, 6)),
]
