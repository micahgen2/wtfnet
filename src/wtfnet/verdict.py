"""Combine all step results into one 'which layer is broken' verdict."""

from __future__ import annotations

from typing import Dict, List, Tuple

from . import sass
from .models import FAIL, LAYERS, OK, SKIP, WARN, StepResult, Verdict


def compute_verdict(results: List[StepResult], target: str) -> Verdict:
    r: Dict[str, StepResult] = {s.key: s for s in results}

    def status(key: str) -> str:
        return r[key].status if key in r else SKIP

    evidence = ["{}: {}".format(s.title, s.status.upper()) for s in results]

    if results and all(s.status == SKIP for s in results):
        h, d, f = sass.verdict("none", WARN, target)
        return Verdict("none", WARN, h, d, f, evidence)

    # Is the internet actually reachable? Ping can be blocked by firewalls, so
    # accept ANY proof of life: a ping reply, a public DNS answer, or a TCP
    # connection (even a refusal means a packet made the round trip).
    alive_via: List[str] = []
    if "internet" in r and r["internet"].data.get("any_reply"):
        alive_via.append("ping")
    if "dns" in r and r["dns"].data.get("public_ok"):
        alive_via.append("public DNS")
    if "ports" in r and r["ports"].data.get("reachable_count"):
        alive_via.append("TCP")
    alive = bool(alive_via)
    if alive:
        evidence.append("Internet is reachable (proved by: {})".format(", ".join(alive_via)))

    problems: List[Tuple[str, str]] = []  # (layer, severity)

    if status("interfaces") == FAIL and not alive:
        problems.append(("local", FAIL))

    gw = status("gateway")
    gw_data = r["gateway"].data if "gateway" in r else {}
    gw_stats = gw_data.get("stats")
    if gw == FAIL and not alive:
        problems.append(("gateway", FAIL))
    elif gw == FAIL and gw_data.get("gateway") is None:
        evidence.append("No default gateway IP found but traffic flows anyway (VPN?)")
    elif gw == FAIL and gw_stats is not None and gw_stats.received == 0:
        evidence.append("Gateway ignores ping but traffic flows anyway (harmless)")
    elif gw in (FAIL, WARN):
        # The router IS answering, just badly (heavy loss or latency): a degraded link.
        problems.append(("gateway", WARN))

    inet = status("internet")
    if not alive and inet in (FAIL, WARN) and gw != FAIL:
        problems.append(("isp", FAIL))
    elif inet == WARN and alive:
        problems.append(("isp", WARN))

    if not alive and not problems:
        # Nothing proves the internet works and nothing upstream is to blame
        # (e.g. ping was unavailable), so the break is somewhere past the router.
        problems.append(("isp", FAIL))

    dns = status("dns")
    if alive and dns == FAIL:
        problems.append(("dns", FAIL))
    elif dns == WARN:
        problems.append(("dns", WARN))

    ports = status("ports")
    if alive and ports == FAIL:
        problems.append(("remote", FAIL))
    elif alive and ports == WARN:
        problems.append(("remote", WARN))
    if alive and "traceroute" in r and not r["traceroute"].data.get("reached"):
        evidence.append("Traceroute never reached the target (many hosts block it)")

    # IPv6 steps only exist when the machine has a global IPv6 address. A broken
    # IPv6 is only a *warning*: IPv4 still works, apps just stall before falling back.
    if "gateway6" in r:
        alive6: List[str] = []
        if "internet6" in r and r["internet6"].data.get("any_reply"):
            alive6.append("ping")
        if "dns6" in r and r["dns6"].data.get("public_ok"):
            alive6.append("public DNS")
        if "ports6" in r and r["ports6"].data.get("reachable_count"):
            alive6.append("TCP")
        if alive6:
            evidence.append("IPv6 is reachable (proved by: {})".format(", ".join(alive6)))
        if alive and not alive6:
            problems.append(("ipv6", WARN))
            evidence.append("IPv6 address present but nothing is reachable over IPv6")
        elif alive6 and status("ports6") == FAIL and status("ports") != FAIL:
            problems.append(("ipv6", WARN))
            evidence.append("{} is reachable over IPv4 but not IPv6".format(target))
        elif not alive and alive6:
            evidence.append("IPv6 works even though IPv4 doesn't")

    # Hard failures beat warnings; within each, the lowest layer is blamed first.
    for severity in (FAIL, WARN):
        hits = sorted((layer for layer, sev in problems if sev == severity), key=LAYERS.index)
        if hits:
            h, d, f = sass.verdict(hits[0], severity, target)
            return Verdict(hits[0], severity, h, d, f, evidence)

    h, d, f = sass.verdict("none", OK, target)
    return Verdict("none", OK, h, d, f, evidence)
