import argparse
import io

import pytest
import samples as S
from conftest import FakeNet
from rich.console import Console

from wtfnet import cli, render


def make_console():
    return Console(file=io.StringIO(), width=100, force_terminal=False, color_system=None)


def factory_for(net):
    def factory(**kw):
        ctx = net.context()
        ctx.target, ctx.ports, ctx.dns_name, ctx.ipv6 = kw["target"], kw["ports"], kw["dns_name"], kw["ipv6"]
        return ctx
    return factory


# --------------------------------------------------------------- parsing
def test_parse_ports_lists_ranges_and_dedupe():
    assert cli.parse_ports("80,443") == [80, 443]
    assert cli.parse_ports("8000-8002, 80,80") == [8000, 8001, 8002, 80]


@pytest.mark.parametrize("bad", ["", "abc", "0", "70000", "9-1", "1-100"])
def test_parse_ports_rejects_nonsense(bad):
    with pytest.raises(argparse.ArgumentTypeError):
        cli.parse_ports(bad)


@pytest.mark.parametrize("bad", ["-f", "x;rm -rf ~", "a b", "$(whoami)", ""])
def test_target_rejects_option_lookalikes_and_shell_junk(bad):
    with pytest.raises(argparse.ArgumentTypeError):
        cli.valid_target(bad)


def test_target_accepts_hosts_and_ips():
    for ok in ("example.com", "192.168.1.1", "my-host.lan"):
        assert cli.valid_target(ok) == ok


def test_defaults_and_watch_flag_forms():
    a = cli.build_parser().parse_args([])
    assert (a.target, a.ports, a.watch, a.html_report, a.quiet) == ("example.com", [80, 443], None, None, False)
    assert cli.build_parser().parse_args(["--watch"]).watch == 30
    assert cli.build_parser().parse_args(["--watch", "10"]).watch == 10
    assert cli.build_parser().parse_args(["--html-report"]).html_report == cli.DEFAULT_REPORT
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["--watch", "1"])


# ------------------------------------------------------------------ runs
def test_full_run_prints_command_output_explanation_and_verdict():
    console = make_console()
    code = cli.main(["--target", "example.com"], console, factory_for(FakeNet()))
    out = console.file.getvalue()
    assert code == 0
    assert "$ ip route show default" in out          # the exact command
    assert "rtt min/avg/max/mdev" in out              # the raw output
    assert "what this means" in out                   # the explanation
    assert "SUMMARY VERDICT" in out and "Everything's fine" in out


def test_exit_code_reflects_severity():
    assert cli.main([], make_console(), factory_for(FakeNet(ports={80: "filtered", 443: "filtered"}))) == 2
    assert cli.main([], make_console(), factory_for(FakeNet(gw_ping=S.PING_LINUX_LOSSY))) == 1


def test_quiet_hides_commands_and_raw_output():
    console = make_console()
    cli.main(["--quiet"], console, factory_for(FakeNet()))
    out = console.file.getvalue()
    assert "$ ping" not in out and "raw output" not in out
    assert "[ OK ]" in out and "SUMMARY VERDICT" in out


def test_square_brackets_in_output_are_not_eaten_by_rich_markup():
    net = FakeNet(trace=S.TRACE_UNIX_REACHED.replace("(93.184.216.34)", "[93.184.216.34]"))
    console = make_console()
    cli.main([], console, factory_for(net))
    assert "[93.184.216.34]" in console.file.getvalue()


def test_html_report_is_written_and_escaped(tmp_path):
    net = FakeNet(trace="<script>alert(1)</script>\n" + S.TRACE_UNIX_REACHED)
    path = tmp_path / "r.html"
    cli.main(["--html-report", str(path), "--quiet"], make_console(), factory_for(net))
    html_text = path.read_text()
    assert "<script>alert(1)</script>" not in html_text
    assert "&lt;script&gt;" in html_text
    assert "Gateway ping" in html_text and "ip route show default" in html_text


def test_watch_runs_repeatedly_until_ctrl_c(tmp_path):
    sleeps = []

    def fake_sleep(n):
        sleeps.append(n)
        if len(sleeps) == 2:
            raise KeyboardInterrupt

    console = make_console()
    path = tmp_path / "w.html"
    code = cli.main(["--watch", "5", "--quiet", "--html-report", str(path)], console,
                    factory_for(FakeNet()), fake_sleep)
    out = console.file.getvalue()
    assert sleeps == [5, 5] and "run #2" in out and "2 runs" in out
    assert path.read_text().count("<h2>Run ") == 2
    assert code == 0


def test_render_first_sentence():
    assert render.first_sentence("One. Two.") == "One."
    assert render.first_sentence("No period") == "No period"
