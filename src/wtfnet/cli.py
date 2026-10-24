"""Command-line entry point: argument parsing, the run loop, watch mode."""

from __future__ import annotations

import argparse
import datetime as dt
import re
import sys
import time
from collections import Counter
from typing import Callable, List, Optional

from rich.console import Console
from rich.markup import escape

from . import __version__, parsers, render
from .checks import STEPS, STEPS6, Context, has_ipv6
from .models import FAIL, OK, WARN, Run
from .platform_cmds import detect_system
from .verdict import compute_verdict

DEFAULT_REPORT = "wtfnet-report.html"
EXIT_CODES = {OK: 0, WARN: 1, FAIL: 2}

# Letters, digits, dots and hyphens only, and no leading hyphen. The leading
# hyphen rule matters: a "host" of "-f" would be read by ping as an option.
_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


def valid_target(text: str) -> str:
    if "%" in text:  # scoped IPv6 like fe80::1%en0 is for gateways, not targets
        raise argparse.ArgumentTypeError("'{}' doesn't look like a hostname or IP address".format(text))
    if parsers.ip_family(text):  # IPv4 or IPv6 literal (a ':' would fail the hostname regex)
        return text
    if not _HOST_RE.match(text):
        raise argparse.ArgumentTypeError(
            "'{}' doesn't look like a hostname or IPv4 address".format(text))
    return text


def parse_ports(text: str) -> List[int]:
    """'80,443,8000-8002' -> [80, 443, 8000, 8001, 8002]"""
    ports: List[int] = []
    try:
        for chunk in text.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "-" in chunk:
                lo, hi = (int(x) for x in chunk.split("-", 1))
                if lo > hi:
                    raise ValueError
                ports.extend(range(lo, hi + 1))
            else:
                ports.append(int(chunk))
    except ValueError:
        raise argparse.ArgumentTypeError("'{}' isn't a valid port list (try 80,443 or 8000-8005)".format(text))
    if not ports:
        raise argparse.ArgumentTypeError("no ports given")
    if any(not 1 <= p <= 65535 for p in ports):
        raise argparse.ArgumentTypeError("ports must be between 1 and 65535")
    if len(ports) > 50:
        raise argparse.ArgumentTypeError("that's a lot of ports (max 50). This is a diagnostic, not nmap")
    return list(dict.fromkeys(ports))  # de-duplicate, keep order


def watch_seconds(text: str) -> int:
    try:
        n = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("'{}' isn't a number of seconds".format(text))
    if n < 5:
        raise argparse.ArgumentTypeError("a full run takes a while; use 5 seconds or more")
    return n


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wtfnet",
        description="Run a network diagnostic battery and find out which layer is fucked.",
        epilog="Exit code: 0 = healthy, 1 = warnings, 2 = a problem was found.",
    )
    p.add_argument("--target", type=valid_target, default="example.com", metavar="HOST",
                   help="host for the traceroute and port checks (default: %(default)s)")
    p.add_argument("--ports", type=parse_ports, default=[80, 443], metavar="LIST",
                   help="TCP ports to check on the target, e.g. 80,443,8000-8005 (default: 80,443)")
    p.add_argument("--dns-name", type=valid_target, default="example.com", metavar="NAME",
                   help="name to look up in the DNS timing test (default: %(default)s)")
    p.add_argument("--watch", nargs="?", const=30, default=None, type=watch_seconds, metavar="SECONDS",
                   help="repeat forever, pausing SECONDS between runs (default: 30). Ctrl-C to stop")
    p.add_argument("--html-report", nargs="?", const=DEFAULT_REPORT, default=None, metavar="FILE",
                   help="also write a self-contained HTML report (default file: %s)" % DEFAULT_REPORT)
    p.add_argument("--no-ipv6", dest="ipv6", action="store_false",
                   help="skip the IPv6 tests (they run automatically if you have a global IPv6 address)")
    p.add_argument("--quiet", action="store_true",
                   help="one line per step plus the verdict; hide commands and raw output")
    p.add_argument("--version", action="version", version="wtfnet " + __version__)
    return p


def run_once(ctx: Context, console: Console, quiet: bool, run_no: int = 0) -> Run:
    started = dt.datetime.now()
    render.print_banner(console, ctx.system, ctx.target, ctx.ports, run_no)
    ctx.state.clear()  # forget everything learned in a previous run (matters for --watch)
    results = []
    steps = list(STEPS)
    i = 0
    while i < len(steps):
        step = steps[i]
        # The spinner shows progress while slow commands (traceroute!) run.
        with console.status("[{}/{}] {}...".format(i + 1, len(steps), step.label), spinner="dots"):
            result = step.fn(ctx)
        if step.key == "interfaces" and has_ipv6(ctx):
            steps.extend(STEPS6)  # we now know this machine has IPv6, so test it too
        results.append(result)
        i += 1
        render.print_step(console, i, len(steps), result, quiet)
    verdict = compute_verdict(results, ctx.target)
    render.print_verdict(console, verdict, quiet)
    return Run(started, results, verdict)


def main(
    argv: Optional[List[str]] = None,
    console: Optional[Console] = None,
    context_factory: Callable[..., Context] = Context,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    args = build_parser().parse_args(argv)
    console = console or Console()
    ctx = context_factory(system=detect_system(), target=args.target, ports=args.ports,
                          dns_name=args.dns_name, ipv6=args.ipv6)

    runs: List[Run] = []
    try:
        while True:
            runs.append(run_once(ctx, console, args.quiet, len(runs) + 1 if args.watch else 0))
            if args.watch is None:
                break
            console.print("\n[dim]Next run in {}s. Ctrl-C to stop.[/dim]".format(args.watch))
            sleep(args.watch)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted. Fine, be that way.[/yellow]")

    if len(runs) > 1:
        tally = Counter(r.verdict.layer for r in runs)
        summary = ", ".join("{} x{}".format(layer, n) for layer, n in tally.most_common())
        console.print("[bold]{} runs. Verdicts: {}[/bold]".format(len(runs), summary))

    if args.html_report and runs:
        with open(args.html_report, "w", encoding="utf-8") as fh:
            fh.write(render.build_html(runs, ctx.system, ctx.target))
        console.print("HTML report written to [bold]{}[/bold]".format(escape(args.html_report)),
                      highlight=False)

    return EXIT_CODES[runs[-1].verdict.status] if runs else 0


if __name__ == "__main__":
    sys.exit(main())
