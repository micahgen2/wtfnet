"""Command-line entry point: argument parsing, the run loop, watch mode."""

from __future__ import annotations

import argparse
import datetime as dt
import difflib
import re
import sys
import time
from collections import Counter
from typing import Callable, List, Optional

from rich.console import Console
from rich.markup import escape

from . import __version__, config, export, parsers, render, sass
from .checks import EXTRA_STEP, STEPS, STEPS6, WIFI_STEP, Context, has_ipv6, has_wifi
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
    p.add_argument("--ping-host", dest="ping_hosts", action="append", default=[], type=valid_target,
                   metavar="HOST", help="also ping this host (repeatable), e.g. your NAS or printer")
    p.add_argument("--no-ipv6", dest="ipv6", action="store_false",
                   help="skip the IPv6 tests (they run automatically if you have a global IPv6 address)")
    p.add_argument("--no-wifi", dest="wifi", action="store_false",
                   help="skip the Wi-Fi check (it runs automatically if you're on Wi-Fi)")
    p.add_argument("--json", action="store_true",
                   help="print machine-readable JSON instead of the pretty output "
                        "(with --watch: one JSON object per line)")
    p.add_argument("--log", default=None, metavar="FILE",
                   help="append every run to FILE: a summary row if it ends in .csv, "
                        "a full JSON line otherwise")
    p.add_argument("--clean", action="store_true",
                   help="safe-for-work mode: swap the profanity for milder words")
    p.add_argument("--config", default=None, metavar="FILE",
                   help="read settings from a TOML file (default: ./wtfnet.toml, then "
                        "the per-user config). Command-line flags win")
    p.add_argument("--quiet", action="store_true",
                   help="one line per step plus the verdict; hide commands and raw output")
    p.add_argument("--version", action="version", version="wtfnet " + __version__)
    return p


def settings_from_config(raw: dict, source: str) -> dict:
    """Validate a parsed config file and turn it into argparse defaults. Raises ConfigError."""
    def bad(key, why):
        raise config.ConfigError("{}: '{}' {}".format(source, key, why))

    def boolean(key, v):
        if not isinstance(v, bool):
            bad(key, "must be true or false")
        return v

    def string(key, v):
        if not isinstance(v, str) or not v:
            bad(key, "must be a non-empty string")
        return v

    def host(key, v):
        try:
            return valid_target(string(key, v))
        except argparse.ArgumentTypeError as exc:
            bad(key, str(exc))

    out: dict = {}
    for key, value in raw.items():
        if key not in config.KEYS:
            near = difflib.get_close_matches(key, config.KEYS, n=1)
            raise config.ConfigError("{}: unknown setting '{}'{}".format(
                source, key, " (did you mean '{}'?)".format(near[0]) if near else ""))
        if key in ("target", "dns_name"):
            out[key] = host(key, value)
        elif key == "ports":
            if isinstance(value, bool):
                bad(key, "must be a port list")
            text = ",".join(str(x) for x in value) if isinstance(value, list) else str(value)
            try:
                out[key] = parse_ports(text)
            except argparse.ArgumentTypeError as exc:
                bad(key, str(exc))
        elif key == "ping_hosts":
            if not isinstance(value, list):
                bad(key, "must be a list of hostnames")
            out[key] = [host(key, h) for h in value]
        elif key in ("ipv6", "wifi", "clean", "quiet"):
            out[key] = boolean(key, value)
        elif key == "watch":
            if isinstance(value, bool) or not isinstance(value, int):
                bad(key, "must be a number of seconds")
            try:
                out[key] = watch_seconds(str(value))
            except argparse.ArgumentTypeError as exc:
                bad(key, str(exc))
        elif key in ("html_report", "log"):
            out[key] = string(key, value)
    return out


def _preparse_config_path(argv: Optional[List[str]]) -> Optional[str]:
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config", default=None)
    return pre.parse_known_args(argv)[0].config


def _clean_verdict(verdict) -> None:
    """--clean: scrub the verdict in place so JSON and HTML inherit it."""
    verdict.headline = sass.clean(verdict.headline)
    verdict.detail = sass.clean(verdict.detail)
    verdict.fixes = [sass.clean(f) for f in verdict.fixes]


def run_once(ctx: Context, console: Console, quiet: bool, run_no: int = 0,
             clean: bool = False) -> Run:
    started = dt.datetime.now()
    render.print_banner(console, ctx.system, ctx.target, ctx.ports, run_no)
    ctx.state.clear()  # forget everything learned in a previous run (matters for --watch)
    results = []
    steps = list(STEPS)
    if ctx.extra_hosts:
        steps.append(EXTRA_STEP)
    i = 0
    while i < len(steps):
        step = steps[i]
        # The spinner shows progress while slow commands (traceroute!) run.
        with console.status("[{}/{}] {}...".format(i + 1, len(steps), step.label), spinner="dots"):
            result = step.fn(ctx)
        if step.key == "interfaces":
            if has_wifi(ctx):
                steps.insert(i + 1, WIFI_STEP)  # on Wi-Fi: the radio is a prime suspect
            if has_ipv6(ctx):
                steps.extend(STEPS6)  # we now know this machine has IPv6, so test it too
        if clean:
            result.explanation = sass.clean(result.explanation)
        results.append(result)
        i += 1
        render.print_step(console, i, len(steps), result, quiet)
    verdict = compute_verdict(results, ctx.target)
    if clean:
        _clean_verdict(verdict)
    render.print_verdict(console, verdict, quiet)
    return Run(started, results, verdict)


def main(
    argv: Optional[List[str]] = None,
    console: Optional[Console] = None,
    context_factory: Callable[..., Context] = Context,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    parser = build_parser()
    try:
        path = config.find_config(_preparse_config_path(argv))
        if path:
            parser.set_defaults(**settings_from_config(config.load_config(path), str(path)))
    except config.ConfigError as exc:
        parser.error(str(exc))
    args = parser.parse_args(argv)

    # In --json mode stdout belongs to the data; chatter goes to stderr.
    info = console or Console(stderr=args.json)
    screen = Console(quiet=True) if args.json else info
    ctx = context_factory(system=detect_system(), target=args.target, ports=args.ports,
                          dns_name=args.dns_name, ipv6=args.ipv6, wifi=args.wifi,
                          extra_hosts=args.ping_hosts)

    runs: List[Run] = []
    log_failed = False
    try:
        while True:
            run = run_once(ctx, screen, args.quiet, len(runs) + 1 if args.watch else 0, args.clean)
            runs.append(run)
            if args.json:
                print(export.run_json(run, ctx.system, ctx.target,
                                      indent=None if args.watch else 2), flush=True)
            if args.log and not log_failed:
                try:
                    export.append_log(args.log, run, ctx.system, ctx.target)
                except OSError as exc:
                    log_failed = True
                    info.print("[red]Can't write the log {}: {}[/red]".format(
                        escape(args.log), escape(str(exc))), highlight=False)
            if args.watch is None:
                break
            info.print("\n[dim]Next run in {}s. Ctrl-C to stop.[/dim]".format(args.watch))
            sleep(args.watch)
    except KeyboardInterrupt:
        info.print("\n[yellow]Interrupted. Fine, be that way.[/yellow]")

    if len(runs) > 1:
        tally = Counter(r.verdict.layer for r in runs)
        summary = ", ".join("{} x{}".format(layer, n) for layer, n in tally.most_common())
        info.print("[bold]{} runs. Verdicts: {}[/bold]".format(len(runs), summary))

    if args.html_report and runs:
        with open(args.html_report, "w", encoding="utf-8") as fh:
            fh.write(render.build_html(runs, ctx.system, ctx.target))
        info.print("HTML report written to [bold]{}[/bold]".format(escape(args.html_report)),
                   highlight=False)

    return EXIT_CODES[runs[-1].verdict.status] if runs else 0


if __name__ == "__main__":
    sys.exit(main())
