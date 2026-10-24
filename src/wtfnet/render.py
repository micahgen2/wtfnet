"""Everything about showing results: rich console output and the HTML report."""

from __future__ import annotations

import html
from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text

from . import __version__
from .models import FAIL, OK, SKIP, WARN, Run, StepResult, Verdict

MAX_RAW_LINES = 50  # console only; the HTML report always has everything

# status -> (rich colour, badge text)
STYLE = {
    OK: ("green", "[ OK ]"),
    WARN: ("yellow", "[WARN]"),
    FAIL: ("red", "[FAIL]"),
    SKIP: ("bright_black", "[SKIP]"),
}


def first_sentence(text: str) -> str:
    cut = text.find(". ")
    return text if cut == -1 else text[: cut + 1]


# NOTE: we wrap every piece of untrusted text in rich's `Text(...)`. Plain
# strings are scanned for [markup] tags, and real command output is full of
# square brackets, e.g. "[93.184.216.34]" in tracert output. That would
# either vanish or crash. Text() prints exactly what it's given.


def print_banner(console: Console, system: str, target: str, ports: List[int], run_no: int = 0) -> None:
    title = "wtfnet v{}".format(__version__)
    if run_no:
        title += "  (run #{})".format(run_no)
    body = Text()
    body.append("OS: ", style="dim")
    body.append(system)
    body.append("   Target: ", style="dim")
    body.append(target, style="bold")
    body.append("   Ports: ", style="dim")
    body.append(",".join(map(str, ports)))
    console.print(Panel(body, title=title, border_style="cyan"))


def print_step(console: Console, index: int, total: int, step: StepResult, quiet: bool = False) -> None:
    color, badge = STYLE[step.status]
    if quiet:
        line = Text()
        line.append(badge + " ", style="bold " + color)
        line.append(step.title + ": ", style="bold")
        line.append(first_sentence(step.explanation))
        console.print(line)
        return

    header = Text()
    header.append("[{}/{}] ".format(index, total), style="bold cyan")
    header.append(step.title + "  ", style="bold")
    header.append(badge, style="bold " + color)
    console.print()
    console.print(Rule(header, style=color))

    for ex in step.execs:
        cmd = Text()
        cmd.append("$ ", style="bold cyan")
        cmd.append(ex.display, style="bold")
        cmd.append("   ({:.2f}s)".format(ex.elapsed), style="dim")
        console.print(cmd)

        lines = ex.output.rstrip().splitlines() or ["(no output)"]
        shown = lines[:MAX_RAW_LINES]
        body = Text("\n".join(shown))
        if len(lines) > MAX_RAW_LINES:
            body.append(
                "\n... {} more lines hidden (use --html-report for everything)".format(
                    len(lines) - MAX_RAW_LINES),
                style="italic",
            )
        console.print(Panel(body, title="raw output", title_align="left",
                            border_style="bright_black", style="dim"))

    console.print(Panel(Text(step.explanation), title="what this means", title_align="left",
                        border_style=color))


def print_verdict(console: Console, verdict: Verdict, quiet: bool = False) -> None:
    color = {OK: "green", WARN: "yellow", FAIL: "red"}[verdict.status]
    body = Text()
    body.append(verdict.headline + "\n\n", style="bold " + color)
    body.append(verdict.detail)
    if verdict.fixes:
        body.append("\n\nTry this, in order:", style="bold")
        for i, fix in enumerate(verdict.fixes, 1):
            body.append("\n  {}. {}".format(i, fix))
    if not quiet and verdict.evidence:
        body.append("\n\nEvidence:", style="bold")
        for item in verdict.evidence:
            body.append("\n  - " + item, style="dim")
    console.print()
    console.print(Panel(body, title="SUMMARY VERDICT", border_style=color, padding=(1, 2)))


# ------------------------------------------------------------------- HTML
_CSS = """
body{font:15px/1.5 system-ui,sans-serif;background:#111418;color:#e6e6e6;max-width:900px;margin:2rem auto;padding:0 1rem}
h1{font-size:1.6rem} h2{margin-top:2.2rem;border-bottom:1px solid #333;padding-bottom:.3rem}
pre{background:#1b1f26;padding:.8rem;border-radius:6px;overflow-x:auto;color:#bbb;font-size:13px}
code.cmd{color:#7fd1ff;font-weight:bold} .badge{padding:.1rem .5rem;border-radius:4px;font-size:.8rem;font-weight:bold;color:#000}
.ok{background:#4caf50}.warn{background:#ffc107}.fail{background:#f44336}.skip{background:#888}
.say{border-left:4px solid #555;padding:.4rem .9rem;background:#191d23;margin:.6rem 0}
.verdict{border:2px solid #555;border-radius:8px;padding:1rem 1.4rem;margin:1.5rem 0;background:#191d23}
.verdict.ok{border-color:#4caf50}.verdict.warn{border-color:#ffc107}.verdict.fail{border-color:#f44336}
.dim{color:#888;font-size:.85rem}
"""


def _esc(s: str) -> str:
    return html.escape(s, quote=True)  # command output is untrusted: always escape


def build_html(runs: List[Run], system: str, target: str) -> str:
    parts = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        "<title>wtfnet report</title><style>{}</style></head><body>".format(_CSS),
        "<h1>wtfnet report</h1>",
        "<p class='dim'>OS: {} &middot; target: {} &middot; wtfnet v{}</p>".format(
            _esc(system), _esc(target), __version__),
    ]
    for n, run in enumerate(runs, 1):
        v = run.verdict
        parts.append("<h2>Run {} &mdash; {}</h2>".format(n, _esc(run.started.strftime("%Y-%m-%d %H:%M:%S"))))
        parts.append("<div class='verdict {}'><h3>{}</h3><p>{}</p>".format(
            v.status, _esc(v.headline), _esc(v.detail)))
        if v.fixes:
            parts.append("<ol>{}</ol>".format("".join("<li>{}</li>".format(_esc(f)) for f in v.fixes)))
        parts.append("</div>")
        for i, step in enumerate(run.results, 1):
            parts.append("<h3>{}. {} <span class='badge {}'>{}</span></h3>".format(
                i, _esc(step.title), step.status, step.status.upper()))
            for ex in step.execs:
                parts.append("<div><code class='cmd'>$ {}</code> <span class='dim'>({:.2f}s)</span></div>".format(
                    _esc(ex.display), ex.elapsed))
                parts.append("<pre>{}</pre>".format(_esc(ex.output.rstrip() or "(no output)")))
            parts.append("<div class='say'>{}</div>".format(_esc(step.explanation)))
    parts.append("</body></html>")
    return "\n".join(parts)
