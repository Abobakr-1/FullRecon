"""Rate-limited HTTP client with retries, scope checks and TLS tolerance.

Built on ``urllib``/``http.client`` from the standard library so the tool has
no mandatory third-party runtime dependency.  ``requests`` is used only when
installed *and* explicitly preferred.
"""

from __future__ import annotations

import gzip
import io
import random
import socket
import ssl
import threading
import time
import zlib
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

from .. import config as config_mod
from ..utils.helpers import read_text
from ..utils.validators import is_ip
from .scope import Scope

try:  # pragma: no cover - optional dependency
    import requests  # type: ignore
    _HAS_REQUESTS = True
except Exception:  # pragma: no cover
    requests = None  # type: ignore
    _HAS_REQUESTS = False


DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "close",
    "Upgrade-Insecure-Requests": "1",
}


@dataclass
class Response:
    url: str
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed: float = 0.0
    error: str = ""
    redirect_chain: List[str] = field(default_factory=list)
    method: str = "GET"

    @property
    def ok(self) -> bool:
        return self.error == "" and self.status > 0

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    @property
    def title(self) -> str:
        from ..utils.helpers import extract_title

        return extract_title(self.body) if "<title" in self.body.lower() else ""

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "status": self.status,
            "elapsed": round(self.elapsed, 3),
            "content_length": len(self.body),
            "server": self.header("server"),
            "content_type": self.header("content-type"),
            "location": self.header("location"),
            "final_url": self.redirect_chain[-1] if self.redirect_chain else self.url,
            "error": self.error,
        }


class RateLimiter:
    """Token-less, sleep-based per-host rate limiter (thread safe)."""

    def __init__(self, rate_per_second: float) -> None:
        self.rate = max(float(rate_per_second or 0), 0.0)
        self._locks: Dict[str, threading.Lock] = {}
        self._next_ok: Dict[str, float] = {}
        self._guard = threading.Lock()

    def _lock_for(self, host: str) -> threading.Lock:
        with self._guard:
            lock = self._locks.get(host)
            if lock is None:
                lock = threading.Lock()
                self._locks[host] = lock
            return lock

    def wait(self, host: str) -> None:
        if self.rate <= 0:
            return
        interval = 1.0 / self.rate
        lock = self._lock_for(host)
        with lock:
            now = time.monotonic()
            target = self._next_ok.get(host, 0.0)
            if target > now:
                time.sleep(target - now)
                now = time.monotonic()
            self._next_ok[host] = now + interval


class HttpClient:
    """Small, predictable HTTP(S) client used by every module."""

    def __init__(self, cfg: config_mod.Config, scope: Scope, logger=None) -> None:
        self.cfg = cfg
        self.scope = scope
        self.log = logger
        self.rate = RateLimiter(cfg.rate_limit)
        self.user_agent = cfg.user_agent
        self.timeout = cfg.timeout
        self.retries = max(int(cfg.retries), 0)
        self.verify_tls = cfg.verify_tls
        self.proxy = cfg.proxy
        self.max_bytes = 2 * 1024 * 1024
        self.stats = {"requests": 0, "blocked": 0, "errors": 0, "status_404": 0}
        self._stats_lock = threading.Lock()
        self._ssl_context = ssl.create_default_context()
        if not self.verify_tls:
            self._ssl_context.check_hostname = False
            self._ssl_context.verify_mode = ssl.CERT_NONE

    # ------------------------------------------------------------------
    def _bump(self, key: str) -> None:
        with self._stats_lock:
            self.stats[key] = self.stats.get(key, 0) + 1

    def _headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers = dict(DEFAULT_HEADERS)
        headers["User-Agent"] = self.user_agent
        if extra:
            headers.update({k: v for k, v in extra.items() if v is not None})
        return headers

    # ------------------------------------------------------------------
    def request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
        follow_redirects: bool = True,
        max_redirects: int = 5,
        read_body: bool = True,
        timeout: Optional[float] = None,
        max_bytes: Optional[int] = None,
        external: bool = False,
    ) -> Response:
        """Perform a request.

        ``external=True`` is reserved for passive-source APIs (crt.sh, urlscan,
        ...) which are third-party services, not the scan target.  Those hosts
        are hard-coded in the modules; user-supplied URLs never take this path.
        """
        if external:
            if not _is_external_source_host(urlsplit(url).hostname or ""):
                self._bump("blocked")
                return Response(url=url, error="external request to non-allowlisted host", method=method)
        else:
            decision = self.scope.allows_url(url)
            if not decision.allowed:
                self._bump("blocked")
                if self.log:
                    self.log.debug("blocked %s (%s)", url, decision.reason)
                return Response(url=url, error=f"out of scope: {decision.reason}", method=method)

        timeout = timeout or self.timeout
        max_bytes = max_bytes or self.max_bytes
        start = time.time()
        attempt = 0
        last_error = ""
        chain: List[str] = []
        current = url
        is_external = external

        while attempt <= self.retries:
            attempt += 1
            self.rate.wait(urlsplit(current).hostname or "")
            self._bump("requests")
            try:
                resp = self._one_request(
                    current, method, headers, body, follow_redirects,
                    max_redirects, read_body, timeout, max_bytes, chain, is_external,
                )
                resp.elapsed = time.time() - start
                resp.redirect_chain = chain
                if resp.status == 404:
                    self._bump("status_404")
                return resp
            except Exception as exc:  # noqa: BLE001 - network errors are expected
                last_error = f"{type(exc).__name__}: {exc}"
                if attempt <= self.retries:
                    time.sleep(0.25 * attempt + random.uniform(0, 0.15))
        self._bump("errors")
        return Response(
            url=url, error=last_error, elapsed=time.time() - start,
            redirect_chain=chain, method=method,
        )

    # ------------------------------------------------------------------
    def _one_request(
        self,
        url: str,
        method: str,
        headers: Optional[Dict[str, str]],
        body: Optional[bytes],
        follow_redirects: bool,
        max_redirects: int,
        read_body: bool,
        timeout: float,
        max_bytes: int,
        chain: List[str],
        external: bool = False,
    ) -> Response:
        from urllib.parse import urljoin

        current = url
        for _ in range(max_redirects + 1):
            parts = urlsplit(current)
            if not parts.hostname:
                raise ValueError("invalid URL")
            scheme = parts.scheme or "http"
            host = parts.hostname
            port = parts.port or (443 if scheme == "https" else 80)
            path = parts.path or "/"
            if parts.query:
                path += "?" + parts.query

            if scheme == "https":
                conn = self._connect_ssl(host, port, timeout)
            else:
                conn = socket.create_connection((host, port), timeout=timeout)
                conn.settimeout(timeout)

            try:
                request_lines = [
                    f"{method} {path} HTTP/1.1",
                    f"Host: {host}",
                ]
                for key, value in self._headers(headers).items():
                    if key.lower() == "host":
                        continue
                    request_lines.append(f"{key}: {value}")
                if body is not None:
                    request_lines.append(f"Content-Length: {len(body)}")
                request_lines.append("")
                request_lines.append("")
                payload = "\r\n".join(request_lines).encode("latin-1", "replace")
                if body:
                    payload += body
                conn.sendall(payload)
                status, resp_headers, raw = _read_response(conn, read_body, max_bytes)
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

            chain.append(current)

            if (
                follow_redirects
                and status in (301, 302, 303, 307, 308)
                and resp_headers.get("location")
            ):
                next_url = urljoin(current, resp_headers["location"])
                redirect_ok = (
                    _is_external_source_host(urlsplit(next_url).hostname or "")
                    if external else self.scope.allows_url(next_url).allowed
                )
                if not redirect_ok:
                    return Response(
                        url=url, status=status, headers=resp_headers,
                        body="" if not read_body else _decode(raw, resp_headers),
                        redirect_chain=chain, method=method,
                    )
                if method == "POST" and status == 303:
                    method, body = "GET", None
                current = next_url
                continue

            return Response(
                url=url,
                status=status,
                headers=resp_headers,
                body="" if not read_body else _decode(raw, resp_headers),
                redirect_chain=chain,
                method=method,
            )
        raise ValueError("too many redirects")

    def _connect_ssl(self, host: str, port: int, timeout: float):
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        context = self._ssl_context
        # SNI must always be sent, even when certificate checks are disabled.
        try:
            return context.wrap_socket(sock, server_hostname=host if not is_ip(host) else None)
        except (ssl.SSLError, OSError):
            # Retry with an explicitly broad TLS configuration for old servers.
            fallback = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            fallback.check_hostname = False
            fallback.verify_mode = ssl.CERT_NONE
            try:
                fallback.minimum_version = ssl.TLSVersion.TLSv1
            except (ValueError, AttributeError):  # pragma: no cover
                pass
            fallback.set_ciphers("DEFAULT:@SECLEVEL=1")
            try:
                sock.close()
            except Exception:
                pass
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.settimeout(timeout)
            return fallback.wrap_socket(sock, server_hostname=host if not is_ip(host) else None)

    # ------------------------------------------------------------------
    def get(self, url: str, **kwargs) -> Response:
        return self.request(url, "GET", **kwargs)

    def head(self, url: str, **kwargs) -> Response:
        kwargs.setdefault("read_body", False)
        return self.request(url, "HEAD", **kwargs)

    def post(self, url: str, data: bytes = b"", **kwargs) -> Response:
        kwargs.setdefault("headers", {})
        kwargs["headers"].setdefault("Content-Type", "application/json")
        return self.request(url, "POST", body=data, **kwargs)

    def fetch_many(self, urls: Iterable[str], workers: int = 10) -> List[Response]:
        from concurrent.futures import ThreadPoolExecutor

        urls = list(urls)
        if not urls:
            return []
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            return list(pool.map(self.get, urls))

    def __repr__(self) -> str:  # pragma: no cover
        return f"<HttpClient rate={self.cfg.rate_limit}/s timeout={self.timeout}s>"


# ---------------------------------------------------------------------------
# Raw HTTP response parsing
# ---------------------------------------------------------------------------


def _read_response(conn, read_body: bool, max_bytes: int) -> Tuple[int, Dict[str, str], bytes]:
    buffer = b""
    while b"\r\n\r\n" not in buffer:
        chunk = conn.recv(65536)
        if not chunk:
            break
        buffer += chunk
        if len(buffer) > 256 * 1024:
            break
    if not buffer:
        raise ConnectionError("empty response")

    head, _, rest = buffer.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status_line = lines[0].decode("latin-1", "replace")
    parts = status_line.split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        raise ConnectionError(f"malformed status line: {status_line[:80]!r}")
    try:
        status = int(parts[1])
    except ValueError:
        raise ConnectionError(f"malformed status code: {parts[1]!r}")

    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        key, _, value = line.partition(b":")
        headers[key.decode("latin-1").strip().lower()] = value.decode("latin-1").strip()

    if not read_body or status in (204, 304) or 100 <= status < 200:
        return status, headers, b""

    data = rest
    if headers.get("transfer-encoding", "").lower() == "chunked":
        data = _dechunk(conn, data, max_bytes)
    else:
        try:
            length = int(headers.get("content-length", "0"))
        except ValueError:
            length = 0
        if length:
            while len(data) < min(length, max_bytes):
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
            data = data[:length]
        else:
            while len(data) < max_bytes:
                try:
                    chunk = conn.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
    return status, headers, data[:max_bytes]


def _dechunk(conn, data: bytes, max_bytes: int) -> bytes:
    out = b""
    while True:
        while b"\r\n" not in data:
            chunk = conn.recv(65536)
            if not chunk:
                return out
            data += chunk
        size_line, _, data = data.partition(b"\r\n")
        try:
            size = int(size_line.split(b";")[0].strip(), 16)
        except ValueError:
            return out
        if size == 0:
            return out
        while len(data) < size + 2:
            chunk = conn.recv(65536)
            if not chunk:
                return out
            data += chunk
        out += data[:size]
        data = data[size + 2:]
        if len(out) >= max_bytes:
            return out[:max_bytes]


def _decode(raw: bytes, headers: Dict[str, str]) -> str:
    encoding = headers.get("content-encoding", "").lower()
    try:
        if "gzip" in encoding:
            raw = gzip.decompress(raw)
        elif "deflate" in encoding:
            try:
                raw = zlib.decompress(raw)
            except zlib.error:
                raw = zlib.decompress(raw, -zlib.MAX_WBITS)
    except Exception:
        pass

    charset = "utf-8"
    content_type = headers.get("content-type", "")
    if "charset=" in content_type.lower():
        charset = content_type.lower().split("charset=")[-1].split(";")[0].strip().strip('"') or "utf-8"
    try:
        return raw.decode(charset, "replace")
    except LookupError:
        return raw.decode("utf-8", "replace")

# ---------------------------------------------------------------------------
# Passive data-source allowlist
# ---------------------------------------------------------------------------

# These are public data providers used for passive enumeration.  Requests to
# them carry no traffic toward the scan target; they only read public datasets.
EXTERNAL_SOURCE_HOSTS = (
    "crt.sh",
    "api.certspotter.com",
    "api.hackertarget.com",
    "api.subdomain.center",
    "urlscan.io",
    "otx.alienvault.com",
    "rapiddns.io",
    "jldc.me",
    "web.archive.org",
    "index.commoncrawl.org",
    "api.github.com",
    "crt.sh",
    "dns.google",
    "cloudflare-dns.com",
    # RDAP / WHOIS registration data (whois module)
    "data.iana.org",
    "rdap.verisign.com",
    "rdap.publicinterestregistry.org",
    "rdap.identitydigital.services",
    "rdap.nic.co",
    "www.registry.google",
    "rdap.nic.me",
    "rdap.centralnic.com",
    "rdap.nominet.uk",
    "rdap.denic.de",
    "rdap.nic.fr",
    "rdap.sidn.nl",
    "rdap.eu",
    "rdap.ca.fury.ca",
    "rdap.auda.org.au",
    "rdap.jprs.jp",
    "rdap.org",
    # ASN / network intelligence (asn module)
    "api.bgpview.io",
    "bgpview.io",
    "rdap.arin.net",
    "whois.arin.net",
    "stat.ripe.net",
    "api.hackertarget.com",
    "ipinfo.io",
)


def _is_external_source_host(host: str) -> bool:
    host = (host or "").lower().strip(".")
    if not host:
        return False
    for allowed in EXTERNAL_SOURCE_HOSTS:
        if host == allowed or host.endswith("." + allowed):
            return True
    return False
