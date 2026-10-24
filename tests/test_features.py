"""Wi-Fi, HTTPS/captive portal, extra pings, JSON/log export, config file and --clean."""

import ast
import csv
import http.server
import io
import json
import re
import threading
from pathlib import Path

import pytest
import samples as S
from conftest import GW, FakeNet
from test_cli import factory_for, make_console

from wtfnet import cli, config, export, parsers, sass
from wtfnet.checks import EXTRA_STEP, STEPS, WIFI_STEP, detect_wifi, has_wifi
from wtfnet.httpcheck import HttpResult, cert_summary, http_probe
from wtfnet.models import FAIL, OK, SKIP, WARN
from wtfnet.verdict import compute_verdict


def battery(net, **kw):
    """Run the steps like cli.run_once does, wifi and extra-host steps included."""
    ctx = net.context(**kw)
    steps, results, i = list(STEPS), [], 0
    if ctx.extra_hosts:
        steps.append(EXTRA_STEP)
    while i < len(steps):
        results.append(steps[i].fn(ctx))
        if steps[i].key == "interfaces" and has_wifi(ctx):
            steps.insert(i + 1, WIFI_STEP)
        i += 1
    return {r.key: r for r in results}, compute_verdict(results, ctx.target)


# ------------------------------------------------------------ Wi-Fi parsers
def test_macos_wifi_parses_and_handles_redacted_ssid():
    w = parsers.parse_wifi(S.WIFI_MACOS_OK, "macos")
    assert w.connected and w.ssid is None  # "<redacted>" is not a real name
    assert (w.channel, w.band, w.signal_dbm, w.noise_dbm, w.rate_mbps) == (149, "5 GHz", -58, -92, 866)
    assert w.snr_db == 34 and w.phy == "802.11ax"


def test_macos_wifi_off():
    assert parsers.parse_wifi(S.WIFI_MACOS_OFF, "macos").connected is False


def test_nmcli_picks_the_active_row_and_unescapes():
    w = parsers.parse_wifi(S.WIFI_NMCLI_OK, "nmcli")
    assert (w.ssid, w.channel, w.band, w.rate_mbps) == ("HomeNet", 36, "5 GHz", 866)
    assert parsers.parse_wifi(S.WIFI_NMCLI_ESCAPED, "nmcli").ssid == "Cafe: Free"
    assert parsers.parse_wifi(S.WIFI_NMCLI_DOWN, "nmcli").connected is False


def test_iwconfig_and_netsh():
    w = parsers.parse_wifi(S.WIFI_IWCONFIG_OK, "iwconfig")
    assert (w.ssid, w.signal_dbm, w.band, w.rate_mbps) == ("HomeNet", -50, "5 GHz", 433.3)
    n = parsers.parse_wifi(S.WIFI_NETSH_OK, "netsh")
    assert n.connected and n.ssid == "HomeNet" and n.channel == 36


def test_garbage_wifi_output_is_none():
    assert parsers.parse_wifi("what even is this", "nmcli") is None


# ------------------------------------------------------- Wi-Fi detection/step
def test_wired_machine_gets_no_wifi_step():
    steps, _ = battery(FakeNet())
    assert "wifi" not in steps


def test_wifi_machine_gets_a_wifi_step_that_passes():
    steps, v = battery(FakeNet(wifi=S.WIFI_NMCLI_OK))
    assert steps["wifi"].status == OK and v.layer == "none"


def test_no_wifi_flag_skips_the_step():
    steps, _ = battery(FakeNet(wifi=S.WIFI_NMCLI_OK), wifi=False)
    assert "wifi" not in steps


def test_weak_wifi_warns_and_is_named_in_the_gateway_verdict():
    steps, v = battery(FakeNet(wifi=S.WIFI_NMCLI_WEAK))
    assert steps["wifi"].status == WARN
    assert (v.layer, v.status) == ("gateway", WARN)
    assert "Wi-Fi" in v.detail or "wi-fi" in v.detail.lower()


def test_macos_detection_only_probes_wifi_when_default_route_is_wifi():
    calls = []

    def fake_run(argv, timeout=30):
        from wtfnet.runner import CommandResult
        calls.append(argv[0])
        out = {"route": S.GATEWAY_MAC,
               "networksetup": "Hardware Port: Wi-Fi\nDevice: en0\n\nHardware Port: Ethernet\nDevice: en5\n"}
        return CommandResult(argv, 0, out[argv[0]], 0.0)

    ctx = FakeNet().context()
    ctx.system, ctx.run = "darwin", fake_run
    assert detect_wifi(ctx) is True  # default route is en0, which is the Wi-Fi port
    assert "system_profiler" not in calls  # detection must stay cheap

    wired = FakeNet().context()
    wired.system = "darwin"
    wired.run = lambda argv, timeout=30: fake_run(argv, timeout)
    from wtfnet.runner import CommandResult
    wired.run = lambda argv, timeout=30: CommandResult(
        argv, 0, S.GATEWAY_MAC.replace("en0", "en5") if argv[0] == "route" else
        "Hardware Port: Wi-Fi\nDevice: en0\n\nHardware Port: Ethernet\nDevice: en5\n", 0.0)
    assert detect_wifi(wired) is False


# ------------------------------------------------------------ HTTP / captive
def test_cert_summary_counts_days():
    cert = {"subject": ((("commonName", "example.com"),),),
            "issuer": ((("organizationName", "Acme CA"),),),
            "notAfter": "Jan  1 00:00:00 2030 GMT"}
    subject, issuer, days = cert_summary(cert, now=1893456000 - 5 * 86400)  # 2030-01-01 minus 5 days
    assert (subject, issuer) == ("example.com", "Acme CA") and 4.9 < days < 5.1


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/generate_204":
            self.send_response(204)
            self.end_headers()
        else:
            body = b"<html>please log in</html>"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def local_server():
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def test_http_probe_reads_a_204_and_a_200(local_server):
    r = http_probe("127.0.0.1", local_server, "/generate_204", tls=False, timeout=3)
    assert r.error is None and r.status == 204 and not r.body.strip()
    r = http_probe("127.0.0.1", local_server, "/", tls=False, timeout=3)
    assert r.status == 200 and "log in" in r.body and r.total_ms is not None


def test_http_probe_never_raises_on_a_closed_port():
    r = http_probe("127.0.0.1", 1, "/", tls=False, timeout=2)
    assert r.error in ("connect", "timeout")


def _http(**kw):
    base = dict(url="https://example.com/", status=200, reason="OK", total_ms=100.0, cert_days_left=90.0)
    base.update(kw)
    return HttpResult(**base)


def test_https_failure_blames_remote():
    net = FakeNet(https=_http(status=None, error="tls_verify", detail="certificate has expired"))
    steps, v = battery(net)
    assert steps["https"].status == FAIL
    assert v.layer == "remote" and any("date and time" in f for f in v.fixes)


def test_5xx_fails_4xx_is_fine():
    assert battery(FakeNet(https=_http(status=503)))[0]["https"].status == FAIL
    assert battery(FakeNet(https=_http(status=404)))[0]["https"].status == OK


def test_expiring_cert_and_slow_response_warn():
    assert battery(FakeNet(https=_http(cert_days_left=3)))[0]["https"].status == WARN
    assert battery(FakeNet(https=_http(total_ms=9000)))[0]["https"].status == WARN


def test_captive_portal_is_blamed_ahead_of_everything_else():
    login = HttpResult("http://connectivitycheck.gstatic.com/generate_204", status=200, body="<html>login",
                       total_ms=40.0)
    steps, v = battery(FakeNet(captive=login))
    assert steps["captive"].status == FAIL and steps["captive"].data["portal"] is True
    assert v.layer == "portal"


def test_redirect_counts_as_portal_and_unreachable_check_is_skipped():
    redir = HttpResult("x", status=302, headers={"location": "http://login.example/"})
    assert battery(FakeNet(captive=redir))[0]["captive"].data["portal"] is True
    down = HttpResult("x", error="timeout", detail="timed out")
    assert battery(FakeNet(captive=down))[0]["captive"].status == SKIP


# --------------------------------------------------------------- extra hosts
def test_extra_ping_hosts_ok_and_down():
    ok = FakeNet(extra_pings={"nas.lan": S.PING_LINUX_OK.replace("1.1.1.1", "nas.lan")})
    steps, v = battery(ok, extra_hosts=["nas.lan"])
    assert steps["hosts"].status == OK and v.layer == "none"
    dead = FakeNet(extra_pings={"nas.lan": S.PING_LINUX_DEAD})
    steps, v = battery(dead, extra_hosts=["nas.lan"])
    assert steps["hosts"].data["down"] == ["nas.lan"]
    assert (v.layer, v.status) == ("hosts", WARN) and "nas.lan" in v.headline


# --------------------------------------------------------------- JSON / log
def run_cli(argv, net=None):
    console = make_console()
    code = cli.main(argv, console, factory_for(net or FakeNet()))
    return code, console.file.getvalue()


def test_json_output_is_valid_and_complete(capsys):
    code, _ = run_cli(["--json"])
    doc = json.loads(capsys.readouterr().out)
    assert code == 0 and doc["verdict"]["layer"] == "none" and doc["target"] == "example.com"
    keys = [s["key"] for s in doc["steps"]]
    assert keys[0] == "interfaces" and "https" in keys and "captive" in keys
    gw = next(s for s in doc["steps"] if s["key"] == "gateway")
    assert gw["commands"][0]["command"] == "ip route show default" and gw["commands"][0]["output"]
    json.dumps(doc)  # round-trips


def test_json_watch_is_json_lines(capsys):
    net = FakeNet()
    console = make_console()
    sleeps = []

    def sleep(n):
        sleeps.append(n)
        if len(sleeps) == 2:
            raise KeyboardInterrupt

    cli.main(["--json", "--watch", "5"], console, factory_for(net), sleep)
    lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    assert len(lines) == 2 and all(json.loads(ln)["steps"] for ln in lines)


def test_csv_log_has_header_once_and_one_row_per_run(tmp_path):
    log = tmp_path / "net.csv"
    run_cli(["--log", str(log)])
    run_cli(["--log", str(log)])
    rows = list(csv.DictReader(log.open()))
    assert len(rows) == 2 and list(rows[0].keys()) == export.CSV_COLUMNS
    assert rows[0]["verdict_layer"] == "none" and float(rows[0]["gateway_ms"]) > 0
    assert rows[0]["dns_system_ms"] != "" and rows[0]["https_ms"] != ""
    assert rows[0]["wifi_dbm"] == ""  # wired: empty, not zero


def test_csv_log_records_wifi_signal(tmp_path):
    log = tmp_path / "net.csv"
    run_cli(["--log", str(log)], FakeNet(wifi=S.WIFI_NMCLI_OK))
    assert list(csv.DictReader(log.open()))[0]["wifi_dbm"] != ""


def test_jsonl_log_gets_full_runs(tmp_path):
    log = tmp_path / "net.jsonl"
    run_cli(["--log", str(log)])
    run_cli(["--log", str(log)])
    lines = log.read_text().splitlines()
    assert len(lines) == 2 and json.loads(lines[0])["steps"]


def test_unwritable_log_is_reported_not_a_crash(tmp_path):
    code, out = run_cli(["--log", str(tmp_path / "nope" / "x.csv")])
    assert code == 0 and "Can't write the log" in out


# -------------------------------------------------------------------- config
def write(tmp_path, text):
    p = tmp_path / "wtfnet.toml"
    p.write_text(text)
    return str(p)


def test_config_sets_defaults_and_cli_overrides_them(tmp_path):
    cfg = write(tmp_path, 'target = "example.org"\nports = [80, 443]\nquiet = true\n')
    _, out = run_cli(["--config", cfg])
    assert "example.org" in out
    _, out = run_cli(["--config", cfg, "--target", "example.net"])
    assert "example.net" in out and "example.org" not in out


def test_config_ports_accept_string_and_list(tmp_path):
    for value in ('"22,80"', "[22, 80]"):
        s = cli.settings_from_config({"ports": [22, 80] if value.startswith("[") else "22,80"}, "t")
        assert s["ports"] == [22, 80]


def test_unknown_config_key_suggests_the_right_one(tmp_path):
    with pytest.raises(config.ConfigError, match="did you mean 'dns_name'"):
        cli.settings_from_config({"dns_nam": "x.com"}, "t")


@pytest.mark.parametrize("raw", [{"ipv6": "yes"}, {"target": "-f"}, {"ports": "99999"},
                                 {"watch": 1}, {"ping_hosts": "nas"}, {"quiet": 1}])
def test_bad_config_values_are_rejected(raw):
    with pytest.raises(config.ConfigError):
        cli.settings_from_config(raw, "t")


def test_missing_explicit_config_is_an_error(tmp_path, capsys):
    with pytest.raises(SystemExit):
        cli.main(["--config", str(tmp_path / "nope.toml")], make_console(), factory_for(FakeNet()))
    assert "not found" in capsys.readouterr().err


def test_invalid_toml_is_an_error(tmp_path, capsys):
    with pytest.raises(SystemExit):
        cli.main(["--config", write(tmp_path, "target = = =")], make_console(), factory_for(FakeNet()))
    assert "valid TOML" in capsys.readouterr().err


def test_example_config_is_itself_valid(tmp_path):
    raw = config._toml.loads(config.EXAMPLE)
    assert cli.settings_from_config(raw, "example")


# --------------------------------------------------------------------- clean
BANNED = re.compile(r"\b(fuck\w*|shit\w*|ass|asses|asshole\w*|dick\w*|damn\w*|hell|bullshit)\b", re.I)


def _all_strings_in_sass():
    tree = ast.parse(Path(sass.__file__).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield node.value
        elif isinstance(node, ast.JoinedStr):
            for part in node.values:
                if isinstance(part, ast.Constant):
                    yield part.value


def test_clean_leaves_no_profanity_anywhere_in_sass_py():
    leaks = [s for s in _all_strings_in_sass()
             if BANNED.search(sass.clean(s)) and not s.startswith(("(", "\\b")) and "|" not in s]
    assert leaks == []


def test_clean_keeps_capitalisation_and_normal_words():
    assert sass.clean("Fuck it.") == "Forget it."
    assert sass.clean("The class assignment") == "The class assignment"
    assert sass.clean("Hello world") == "Hello world"


def test_clean_flag_scrubs_pretty_json_and_html(tmp_path, capsys):
    dead = FakeNet(gw_ping=S.PING_LINUX_DEAD.replace("8.8.8.8", GW), cf_ping=S.PING_LINUX_DEAD,
                   g_ping=S.PING_LINUX_DEAD, ports={80: "filtered", 443: "filtered"})
    report = tmp_path / "r.html"
    _, out = run_cli(["--clean", "--json", "--html-report", str(report)], dead)
    doc = json.loads(capsys.readouterr().out)
    texts = [doc["verdict"]["headline"], doc["verdict"]["detail"], *doc["verdict"]["fixes"],
             *(s["explanation"] for s in doc["steps"])]
    assert not any(BANNED.search(t) for t in texts)
    html_text = re.sub(r"<[^>]+>", " ", report.read_text())
    assert "Verdict" in html_text or "verdict" in html_text.lower()
    # The raw command output may legitimately contain anything; our own voice must be clean.
    assert not BANNED.search(doc["verdict"]["headline"])
