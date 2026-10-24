"""A tiny HTTP(S) client that times every phase and inspects the TLS certificate.

We use raw sockets instead of urllib so we can measure DNS, TCP connect, TLS
handshake and time-to-first-byte separately. When a page is slow, *which*
phase is slow tells you where to look.
"""

from __future__ import annotations

import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from . import __version__


@dataclass
class HttpResult:
    url: str
    status: Optional[int] = None
    reason: str = ""
    headers: Dict[str, str] = field(default_factory=dict)  # lower-cased names
    body: str = ""  # the first few hundred bytes
    error: Optional[str] = None  # dns | connect | timeout | tls_verify | tls | http
    detail: str = ""
    ip: Optional[str] = None
    dns_ms: Optional[float] = None
    connect_ms: Optional[float] = None
    tls_ms: Optional[float] = None
    ttfb_ms: Optional[float] = None
    total_ms: Optional[float] = None
    tls_version: Optional[str] = None
    cert_subject: Optional[str] = None
    cert_issuer: Optional[str] = None
    cert_days_left: Optional[float] = None


def _ms(since: float) -> float:
    return (time.monotonic() - since) * 1000.0


def _flatten_name(rdns) -> Optional[str]:
    """ssl.getpeercert() gives names as (((key, value),), ...). Prefer the common name."""
    pairs = [kv for group in (rdns or ()) for kv in group]
    for wanted in ("commonName", "organizationName"):
        for key, value in pairs:
            if key == wanted:
                return value
    return pairs[0][1] if pairs else None


def cert_summary(cert: dict, now: Optional[float] = None) -> Tuple[Optional[str], Optional[str], Optional[float]]:
    """(subject, issuer, days until expiry) from an ssl.getpeercert() dict."""
    subject = _flatten_name(cert.get("subject"))
    issuer = None
    pairs = [kv for group in (cert.get("issuer") or ()) for kv in group]
    for wanted in ("organizationName", "commonName"):
        issuer = next((v for k, v in pairs if k == wanted), None)
        if issuer:
            break
    days = None
    if cert.get("notAfter"):
        expires = ssl.cert_time_to_seconds(cert["notAfter"])
        days = (expires - (now if now is not None else time.time())) / 86400.0
    return subject, issuer, days


def http_probe(host: str, port: int = 443, path: str = "/", tls: bool = True,
               timeout: float = 5.0, family: int = 4) -> HttpResult:
    """GET one URL over one IP version. Never raises; problems land in `.error`."""
    scheme = "https" if tls else "http"
    shown_port = "" if port == (443 if tls else 80) else ":{}".format(port)
    r = HttpResult(url="{}://{}{}{}".format(scheme, host, shown_port, path))
    start = time.monotonic()
    af = socket.AF_INET6 if family == 6 else socket.AF_INET

    t = time.monotonic()
    try:
        fam, kind, proto, _, addr = socket.getaddrinfo(host, port, af, socket.SOCK_STREAM)[0]
    except socket.gaierror as exc:
        r.error, r.detail = "dns", "can't resolve {} ({})".format(host, exc)
        return r
    r.dns_ms, r.ip = _ms(t), addr[0]

    raw = socket.socket(fam, kind, proto)
    sock = raw
    try:
        raw.settimeout(timeout)
        t = time.monotonic()
        raw.connect(addr)
        r.connect_ms = _ms(t)
        if tls:
            t = time.monotonic()
            sock = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
            r.tls_ms, r.tls_version = _ms(t), sock.version()
            r.cert_subject, r.cert_issuer, r.cert_days_left = cert_summary(sock.getpeercert())

        request = ("GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: wtfnet/{}\r\n"
                   "Accept: */*\r\nConnection: close\r\n\r\n").format(path, host, __version__)
        t = time.monotonic()
        sock.sendall(request.encode("ascii"))
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 65536:
            chunk = sock.recv(4096)
            if r.ttfb_ms is None:
                r.ttfb_ms = _ms(t)
            if not chunk:
                break
            data += chunk

        head, _, rest = data.partition(b"\r\n\r\n")
        lines = head.decode("iso-8859-1").split("\r\n")
        m = re.match(r"HTTP/\d(?:\.\d)? (\d{3}) ?(.*)", lines[0]) if lines and lines[0] else None
        if not m:
            r.error, r.detail = "http", "that wasn't an HTTP response: {!r}".format(lines[0][:60] if lines else "")
            return r
        r.status, r.reason = int(m.group(1)), m.group(2)
        for line in lines[1:]:
            name, _, value = line.partition(":")
            if value:
                r.headers[name.strip().lower()] = value.strip()
        r.body = rest[:512].decode("utf-8", "replace")
    except socket.timeout:
        r.error, r.detail = "timeout", "no response within {:g}s".format(timeout)
    except ssl.SSLCertVerificationError as exc:  # before SSLError: it is a subclass
        r.error, r.detail = "tls_verify", getattr(exc, "verify_message", None) or str(exc)
    except ssl.SSLError as exc:
        r.error, r.detail = "tls", str(exc)
    except OSError as exc:
        r.error, r.detail = "connect", str(exc)
    finally:
        sock.close()
        if sock is not raw:
            raw.close()
        r.total_ms = _ms(start)
    return r


def format_http(r: HttpResult) -> str:
    """The 'raw output' shown for an HTTP probe."""
    lines = []
    if r.error:
        lines.append("GET {}  ->  FAILED ({})".format(r.url, r.error))
        lines.append(r.detail)
    else:
        lines.append("GET {}  ->  {} {}".format(r.url, r.status, r.reason).rstrip())
    timings = []
    for label, value in (("dns", r.dns_ms), ("tcp connect", r.connect_ms), ("tls", r.tls_ms),
                         ("first byte", r.ttfb_ms), ("total", r.total_ms)):
        if value is not None:
            timings.append("{} {:.0f} ms".format(label, value))
    if timings:
        lines.append(("resolved {} | ".format(r.ip) if r.ip else "") + " | ".join(timings))
    if r.tls_version:
        lines.append("{}, certificate for {}, issued by {}, expires in {:.0f} days".format(
            r.tls_version, r.cert_subject or "?", r.cert_issuer or "?",
            r.cert_days_left if r.cert_days_left is not None else float("nan")))
    for header in ("server", "location", "content-type"):
        if header in r.headers:
            lines.append("{}: {}".format(header, r.headers[header]))
    return "\n".join(lines)
