# wtfnet

A network diagnostic battery with an attitude problem. It runs the checks you'd
run by hand when "the internet is broken", shows you **the exact command**, the
**raw output**, and a **plain-English (profane) explanation**, then names the
layer most likely at fault: **local, gateway, captive portal, ISP, DNS, remote, your own hosts, or IPv6**.

Works on Windows, macOS and Linux. Dependencies: [`rich`](https://github.com/Textualize/rich), plus `tomli` on Python older than 3.11 (for the config file).

## Install

```bash
cd wtfnet
python3 -m venv .venv            # a private folder of packages just for this project
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"          # -e = editable: code changes take effect immediately
```

## Use

```bash
wtfnet                                   # run everything against example.com
wtfnet --target github.com --ports 22,80,443
wtfnet --ports 8000-8005                 # ranges work too
wtfnet --no-ipv6                         # skip the IPv6 tests
wtfnet --target 2606:4700:4700::1111     # IPv6 literals work as targets too
wtfnet --quiet                           # one line per step + the verdict
wtfnet --watch 60                        # re-run every 60s until Ctrl-C (bare --watch = 30s)
wtfnet --html-report                     # also write wtfnet-report.html (or --html-report out.html)
wtfnet --ping-host 192.168.1.50 --ping-host nas.lan   # also ping your own machines
wtfnet --json > run.json                 # machine-readable output for scripts
wtfnet --watch 60 --log net.csv          # append a row per run, then graph it later
wtfnet --clean                           # safe-for-work voice
wtfnet --config ~/office.toml            # settings from a file
python -m wtfnet                         # same thing without installing the script
```

| Flag | What it does |
| --- | --- |
| `--target HOST` | Host for the traceroute and TCP checks (default `example.com`) |
| `--ports LIST` | TCP ports, e.g. `80,443,8000-8005` (default `80,443`, max 50) |
| `--dns-name NAME` | Name to look up in the DNS test (default `example.com`) |
| `--watch [SECONDS]` | Repeat forever. Good for catching flaky connections. Combine with `--quiet --html-report` for a log you can show your ISP |
| `--html-report [FILE]` | Self-contained HTML with every command and full output (the console truncates very long output) |
| `--no-ipv6` | Never run the IPv6 steps (by default they run automatically if you have a global IPv6 address) |
| `--no-wifi` | Never inspect the Wi-Fi link (by default it's checked automatically when you're on Wi-Fi) |
| `--ping-host HOST` | Also ping HOST. Repeatable. A dead one is a warning, never a reason to blame your ISP |
| `--json` | Print the whole run as JSON on stdout (pretty for one run; with `--watch`, one object per line). Progress goes to stderr |
| `--log FILE` | Append every run to FILE. `.csv` gets one summary row per run (latency, loss, DNS and HTTPS timings, Wi-Fi dBm); any other name gets the full run as a JSON line |
| `--clean` | Safe-for-work: swaps the profanity for milder words in the console, JSON and HTML |
| `--config FILE` | Read settings from a TOML file (see below) |
| `--quiet` | Hide commands and raw output |

**Exit codes:** `0` healthy, `1` warnings, `2` problem found. Handy in scripts.

## Config file

Defaults can live in a TOML file so you don't retype them. wtfnet looks for
`--config FILE`, then `./wtfnet.toml`, then `~/.config/wtfnet/config.toml`
(`%APPDATA%\wtfnet\config.toml` on Windows). Command-line flags always win.
Copy [`wtfnet.example.toml`](wtfnet.example.toml) to start. Typos in key names
are rejected with a "did you mean" hint rather than silently ignored.

```toml
target = "github.com"
ports = [22, 443]
ping_hosts = ["192.168.1.50"]
clean = true
```

## What it runs (and why)

Each step answers one question, moving outward from your keyboard. A problem
at one layer usually causes failures further out, which is why the order matters.

| # | Step | Commands (Linux / macOS / Windows) | Question |
| - | ---- | ---------------------------------- | -------- |
| 1 | Local interfaces | `ip -o -4 addr show` / `ifconfig` / `ipconfig /all` | Do I even have an IP address? (`169.254.x.x` means DHCP failed.) |
| 2 | Gateway ping | `ip route show default` / `route -n get default` / `route print -4 0.0.0.0`, then `ping` the result | Can I reach my router? |
| 3 | Internet ping | `ping 1.1.1.1`, `ping 8.8.8.8` | Can I reach the internet **by IP**, with no DNS involved? |
| 4 | DNS timing | `nslookup example.com`, `... 1.1.1.1`, `... 8.8.8.8` | Does name resolution work, and is my resolver slower than public ones? |
| 5 | Traceroute | `traceroute -n` / `tracert -d` | Where along the path do packets stop? |
| 6 | TCP ports | Python `socket.create_connection` (like `nc -zv host port`) | Is the service actually accepting connections? |
| 7 | HTTPS request | Python sockets (like `curl -v https://host/`) | Does a real, verified HTTPS request work? Times DNS / connect / TLS / first byte, checks the certificate's expiry |
| 8 | Captive portal | Python GET of `http://connectivitycheck.gstatic.com/generate_204` | Is a hotel/cafe login page intercepting your traffic? A clean network answers with an empty `204` |

Two steps appear only when they apply:

- **Wi-Fi link** (after step 1, when your default route is Wi-Fi): network name,
  signal strength (dBm), signal-to-noise, channel/band and link speed, from
  `system_profiler` / `nmcli` (or `iwconfig`) / `netsh wlan show interfaces`.
  A weak radio is reported as a degraded **gateway** link, with the numbers.
- **Extra hosts** (when you pass `--ping-host`): pings each one.

### IPv6 (five more steps, added automatically)

If step 1 finds a **global** IPv6 address (`2xxx:` or `3xxx:`, not the `fe80::`
link-local one every interface has, and not a private `fd..` one), five more
steps run, mirroring the IPv4 ones. No global address means they're skipped and
step 1 says so, because plenty of ISPs still don't do IPv6.

| # | Step | Commands (Linux / macOS / Windows) |
| - | ---- | ---------------------------------- |
| a | IPv6 gateway ping | `ip -6 route show default` / `route -n get -inet6 default` / `route print -6`, then ping it |
| b | IPv6 internet ping | `ping -6` / `ping6` / `ping -6` to Cloudflare and Google's IPv6 addresses |
| c | IPv6 DNS | `nslookup -type=AAAA` via your resolver and over IPv6 to the public ones |
| d | IPv6 traceroute | `traceroute -6` / `traceroute6` / `tracert -6` (skipped if the IPv6 pings failed) |
| e | IPv6 TCP ports | same ports as step 6, forced over IPv6 |

Things that differ from IPv4 and might trip you up: the IPv6 default gateway is
a link-local address (`fe80::1`) that can only be pinged with its interface
attached (`fe80::1%en0`), so wtfnet adds that; Windows IPv6 ping replies have no
TTL; and a name with no AAAA record (an IPv4-only site) is *skipped*, not failed.

TCP states: **open** = handshake completed; **closed** = host answered "nobody's
listening" (so it's alive); **filtered** = total silence (firewall or dead host).

Handy to know: pinging an **IP** (step 3) vs. a **name** (step 4) separates "the
internet is down" from "DNS is down". That's the single most useful trick in network troubleshooting.

## How the verdict works

`verdict.py` is deliberately cautious, because ping is often blocked by firewalls:

1. **Is the internet alive?** Any proof counts: a ping reply, a public DNS
   answer, or a TCP connection (even a refusal). If so, failed pings are
   downgraded to "harmless" and the router isn't blamed for ignoring ICMP.
2. **If it's not alive**, blame the lowest broken layer: no IP → **local**;
   router silent → **gateway**; router fine but nothing beyond → **ISP**.
3. **If it is alive**, look for degradation: lossy/slow router → **gateway
   (degraded)** (usually Wi-Fi); lossy internet → **ISP**; system resolver
   failing/slow while public ones work → **DNS**; target's ports dead → **remote**.
4. **IPv6** is judged separately and is only ever a *warning*, because IPv4
   still works. Triggers: you have an IPv6 address but nothing is reachable over
   IPv6, or the target answers over IPv4 but not IPv6. That's the classic "some
   sites hang for 5 seconds" bug (apps wait on IPv6 before falling back).
5. **Captive portal**: if the 204 check gets a login page or a redirect, that's
   blamed first (**portal**), because it makes DNS and web requests look broken
   while pings still work. **HTTPS** failures (bad certificate, 5xx, timeouts) count
   toward **remote**; a TLS error also hints at checking your computer's clock.
6. Hard failures beat warnings; within each, the lowest layer wins.

Tunable thresholds (what counts as "slow") are constants at the top of `checks.py`.

## Project layout

```
src/wtfnet/
  platform_cmds.py  every OS difference lives here (flags, command names)
  runner.py         runs commands safely (no shell), captures output, never raises
  parsers.py        raw text -> data (pure functions, no I/O)
  checks.py         the steps; talks to the OS only through a Context
  verdict.py        combines the steps into one blame decision
  sass.py           ALL the jokes. Edit the voice here without touching logic
  httpcheck.py      raw-socket HTTP(S) client with per-phase timing + cert check
  export.py         --json and --log (CSV / JSON lines)
  config.py         finding and reading the TOML config file
  render.py         rich console output + HTML report
  cli.py            argparse, run loop, watch mode
tests/              151 tests; command output is mocked, no network needed
```

## Tests

```bash
pytest
```

Tests never touch your network. `tests/conftest.py` has a `FakeNet` that stands
in for the OS and returns canned `ping`/`nslookup`/`traceroute` output
(`tests/samples.py`, in Linux, macOS and Windows flavours). Scenarios cover a
healthy network, DHCP failure, dead router, dead ISP, broken DNS, a down
server, lossy Wi-Fi, ICMP-blocked networks, and missing tools.

## Safety notes

- Commands run as argument lists, **never through a shell**, and `--target` is
  validated, so a "hostname" like `x; rm -rf ~` or `-f` is rejected.
- Everything is read-only: pings, lookups, a traceroute and a few TCP connects.
  Nothing is changed on your machine. Don't point `--ports` at hosts you don't
  own as a substitute for a port scanner; it's capped at 50 ports on purpose.
- HTML report output is escaped, so hostile command output can't inject markup.

## Known limitations

- IPv6-only networks (e.g. NAT64 mobile hotspots) aren't judged properly: the IPv4
  steps will fail and the verdict will blame the ISP, though it does note that IPv6 works.
- The IPv6 gateway ping and the Windows/Linux IPv6 commands are covered by tests
  using sample output, but have only been run live on macOS.
- Output parsing assumes English. On Linux/macOS we force `LC_ALL=C`; on a
  non-English Windows the parsers may fail, and the step then says it can't read the output.
- Some minimal Linux installs lack `ping`, `traceroute` or `nslookup`
  (`apt install iputils-ping traceroute dnsutils`). Missing tools are skipped
  and reported, not crashed on.
- DNS timings include process start-up (~10-30 ms) and caching, so compare them to each other, not to absolutes.
- A VPN can legitimately hide the default gateway; the verdict accounts for that when traffic is flowing.
- Wi-Fi: modern macOS hides the network name (`<redacted>`) from tools without Location
  permission, and `system_profiler` takes ~10 s, so that step is slow (only on Wi-Fi).
  The Linux/Windows Wi-Fi parsers are tested against sample output but have not been run live.
- `--clean` is a word-swap over the written voice; text you didn't write (hostnames, raw tool output) is left as-is.

## License

[MIT](LICENSE)
