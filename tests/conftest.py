"""A fake operating system for the tests.

FakeNet is passed to the checks as their `run` function. When the checks ask
to run `ping 1.1.1.1`, FakeNet returns canned output instead of touching
the network. Each scenario below is a different way for a network to break.

Pass v6=True to give the fake machine a global IPv6 address (which makes the
IPv6 steps run); every v6_* knob then controls how the IPv6 side behaves.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
import samples as S  # noqa: E402

from wtfnet.checks import Context, TcpResult  # noqa: E402
from wtfnet.runner import CommandResult  # noqa: E402

GW = "192.168.1.1"
GW6 = "fe80::1%wlan0"
CF6, G6 = "2606:4700:4700::1111", "2001:4860:4860::8888"


class FakeNet:
    def __init__(self, ifaces=None, gateway=S.GATEWAY_LINUX, gw_ping=None, cf_ping=None,
                 g_ping=None, dns=None, trace=S.TRACE_UNIX_REACHED, ports=None, missing=(),
                 v6=False, gateway6=S.GATEWAY6_LINUX, gw6_ping=None, cf6_ping=None, g6_ping=None,
                 dns6=None, trace6=S.TRACE6_UNIX_REACHED, ports6=None):
        self.ifaces = ifaces if ifaces is not None else (S.IFACES_IP_V6 if v6 else S.IFACES_IP)
        self.gateway = gateway
        self.pings = {GW: gw_ping or S.PING_LINUX_OK.replace("1.1.1.1", GW),
                      "1.1.1.1": cf_ping or S.PING_LINUX_OK,
                      "8.8.8.8": g_ping or S.PING_LINUX_OK.replace("1.1.1.1", "8.8.8.8"),
                      GW6: gw6_ping or S.PING6_LINUX_OK.replace(CF6, GW6),
                      CF6: cf6_ping or S.PING6_LINUX_OK,
                      G6: g6_ping or S.PING6_LINUX_OK.replace(CF6, G6)}
        # which nslookup server -> output; None = system resolver
        self.dns = {None: S.NSLOOKUP_UNIX_OK, "1.1.1.1": S.NSLOOKUP_UNIX_OK, "8.8.8.8": S.NSLOOKUP_UNIX_OK}
        self.dns.update(dns or {})
        self.dns6 = {None: S.NSLOOKUP_AAAA_OK, CF6: S.NSLOOKUP_AAAA_OK, G6: S.NSLOOKUP_AAAA_OK}
        self.dns6.update(dns6 or {})
        self.gateway6 = gateway6
        self.trace, self.trace6 = trace, trace6
        self.ports = ports if ports is not None else {80: "open", 443: "open"}
        self.ports6 = ports6 if ports6 is not None else dict(self.ports)
        self.missing = set(missing)  # commands that "aren't installed"
        self.calls = []

    def __call__(self, argv, timeout=30):
        self.calls.append(argv)
        cmd = argv[0]
        if cmd in self.missing:
            return CommandResult(argv, None, "command not found: " + cmd, 0.0, "not_found")
        if cmd == "ip" and argv[1] == "-o":
            out = self.ifaces
        elif cmd == "ip" and argv[1] == "-6":
            out = self.gateway6
        elif cmd == "ip":
            out = self.gateway
        elif cmd == "ping":
            out = self.pings[argv[-1]]
        elif cmd == "nslookup":
            positional = [a for a in argv[1:] if not a.startswith("-")]
            server = positional[1] if len(positional) > 1 else None
            out = (self.dns6 if "-type=AAAA" in argv else self.dns)[server]
        elif cmd == "traceroute":
            out = self.trace6 if "-6" in argv else self.trace
        else:
            raise AssertionError("unexpected command: %r" % (argv,))
        return CommandResult(argv, 0, out, 0.05)

    def tcp(self, host, port, timeout, family=4):
        state = (self.ports6 if family == 6 else self.ports)[port]
        detail = {"filtered": "timed out after 3s", "noaddr": "%s has no IPv6 (AAAA) address" % host}.get(state, "")
        return TcpResult(port, state, 20.0 if state in ("open", "closed") else None, detail)

    def context(self, **kw):
        kw.setdefault("target", "example.com")
        return Context(system="linux", ports=sorted(self.ports), run=self,
                       tcp_connect=self.tcp, which=lambda name: "/usr/bin/" + name,
                       resolve=lambda name, family=4: ["93.184.216.34" if family == 4 else CF6], **kw)


@pytest.fixture
def healthy():
    return FakeNet()


@pytest.fixture
def healthy6():
    return FakeNet(v6=True)
