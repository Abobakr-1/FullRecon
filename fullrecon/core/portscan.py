"""TCP port scanning with optional nmap service/version detection."""

from __future__ import annotations

import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence

from .. import config as config_mod
from ..utils.helpers import run_command, tool_available
from .scope import Scope

try:  # optional
    import dns.resolver  # type: ignore
    _HAS_DNS = True
except Exception:  # pragma: no cover
    _HAS_DNS = False


KNOWN_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    443: "https", 445: "microsoft-ds", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs",
    2375: "docker", 3000: "http-alt", 3306: "mysql", 3389: "rdp", 5000: "http-alt",
    5432: "postgresql", 5601: "kibana", 5900: "vnc", 6379: "redis", 7001: "weblogic",
    8000: "http-alt", 8008: "http-alt", 8080: "http-proxy", 8081: "http-alt",
    8088: "http-alt", 8443: "https-alt", 8888: "http-alt", 9000: "http-alt",
    9090: "http-alt", 9200: "elasticsearch", 9443: "https-alt", 10000: "webmin",
    11211: "memcached", 27017: "mongodb",
}

# Ports that should not normally be exposed to the internet, grouped by the
# risk they represent.  SSH on 22 is routine for servers, so it is "notable"
# rather than "critical"; an unauthenticated database is different.
UNUSUAL_PORTS = {
    22, 23, 135, 139, 445, 1433, 1521, 2049, 2375, 3306, 3389, 5432, 5601,
    5900, 6379, 9200, 11211, 27017,
}

# Unauthenticated-by-default or remote-desktop style services.
CRITICAL_PORTS = {
    23,      # telnet (cleartext)
    2375,    # docker API (no auth by default)
    6379,    # redis
    9200,    # elasticsearch
    11211,   # memcached
    27017,   # mongodb
    3306,    # mysql
    5432,    # postgresql
    1433,    # mssql
    5900,    # VNC
    3389,    # RDP
}

# Administrative services that are expected on servers but worth inventorying.
ADMIN_PORTS = {22, 135, 139, 445, 1521, 2049, 5601}


@dataclass
class PortResult:
    host: str
    port: int
    state: str = "open"
    service: str = ""
    version: str = ""
    banner: str = ""

    def line(self) -> str:
        service = self.service or KNOWN_SERVICES.get(self.port, "unknown")
        detail = f" {self.version}" if self.version else ""
        return f"{self.host}:{self.port} {service}{detail}".rstrip()

    def to_dict(self) -> dict:
        return {
            "host": self.host, "port": self.port, "state": self.state,
            "service": self.service or KNOWN_SERVICES.get(self.port, "unknown"),
            "version": self.version, "banner": self.banner[:300],
        }


def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    """Read a short service banner where the protocol sends one first."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(512)
            return data.decode("latin-1", "replace").strip()
    except Exception:
        return ""


def scan_port(host: str, port: int, timeout: float = 2.0) -> Optional[PortResult]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return PortResult(host=host, port=port, service=KNOWN_SERVICES.get(port, ""))
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


class PortScanner:
    def __init__(self, cfg: config_mod.Config, scope: Scope, logger=None) -> None:
        self.cfg = cfg
        self.scope = scope
        self.log = logger
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    def resolve(self, host: str) -> List[str]:
        from ..utils.validators import is_ip

        if is_ip(host):
            return [host]
        if _HAS_DNS:
            try:
                answers = dns.resolver.resolve(host, "A")
                return sorted({str(r) for r in answers})
            except Exception:
                pass
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_INET)
            return sorted({info[4][0] for info in infos})
        except socket.gaierror:
            return []

    def scan_host(self, host: str, ports: Sequence[int]) -> List[PortResult]:
        """Scan one host. Scope is enforced per resolved IP and per port."""
        if not self.scope.allows_host(host).allowed:
            if self.log:
                self.log.debug("port scan skipped (scope): %s", host)
            return []

        addresses = self.resolve(host) or [host]
        results: List[PortResult] = []
        allowed_ports = [p for p in ports if self.scope.allows_port(p).allowed]
        if not allowed_ports:
            return []

        # Prefer nmap for speed/accuracy when available.
        if self.cfg.use_nmap and tool_available("nmap"):
            nmap_results = self._nmap(host, addresses, allowed_ports)
            if nmap_results is not None:
                return nmap_results

        for address in addresses:
            # The address came from resolving an in-scope hostname, so it is a
            # legitimate scan target. Record results against the hostname the
            # user asked about, not the resolved IP.
            found = self._connect_scan(address, allowed_ports)
            for item in found:
                item.host = host
            results.extend(found)
        return self._merge(results)

    def _connect_scan(self, address: str, ports: Sequence[int]) -> List[PortResult]:
        found: List[PortResult] = []
        workers = max(1, min(self.cfg.port_scan_threads, len(ports) or 1))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(scan_port, address, port, self.cfg.port_scan_timeout): port
                for port in ports
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
        return found

    # ------------------------------------------------------------------
    def _nmap(self, host: str, addresses: List[str], ports: Sequence[int]) -> Optional[List[PortResult]]:
        args = ["nmap", "-Pn", "--open", "-T4", "-p", ",".join(map(str, ports))]
        if self.cfg.nmap_service_detection:
            args += ["-sV", "--version-light", "--host-timeout", "300s"]
        args += [host]
        code, stdout, stderr = run_command(args, timeout=600)
        if code != 0 or not stdout:
            if self.log:
                self.log.debug("nmap failed (%s): %s", code, (stderr or "").strip()[:200])
            return None
        results = self._parse_nmap(stdout)
        if results:
            # nmap prints one section per address it reached (hostname and/or
            # IP).  Results belong to the hostname we asked about, and the same
            # port must never appear twice.
            folded: Dict[int, PortResult] = {}
            for item in results:
                existing = folded.get(item.port)
                if existing is None or (item.version and not existing.version):
                    folded[item.port] = PortResult(
                        host=host, port=item.port, state=item.state,
                        service=item.service, version=item.version, banner=item.banner,
                    )
            results = [folded[p] for p in sorted(folded)]
        if not results:
            # Port list may be too small for nmap to be useful; fall back.
            return None
        return results

    @staticmethod
    def _parse_nmap(output: str) -> List[PortResult]:
        results: List[PortResult] = []
        current_host = ""
        for raw_line in output.splitlines():
            line = raw_line.strip()
            if line.startswith("Nmap scan report for"):
                rest = line[len("Nmap scan report for"):].strip()
                if "(" in rest and rest.endswith(")"):
                    current_host = rest.split("(")[-1].rstrip(")")
                else:
                    current_host = rest
                continue
            if "/tcp" not in line or "open" not in line.split():
                continue
            fields = line.split()
            try:
                port = int(fields[0].split("/")[0])
            except (ValueError, IndexError):
                continue
            state = fields[1] if len(fields) > 1 else "open"
            service = fields[2] if len(fields) > 2 else KNOWN_SERVICES.get(port, "")
            version = " ".join(fields[3:]).strip()
            results.append(PortResult(
                host=current_host or "", port=port, state=state,
                service=service, version=version,
            ))
        return results

    @staticmethod
    def _merge(results: List[PortResult]) -> List[PortResult]:
        """De-duplicate by (host, port), preferring entries with version data.

        A hostname and the IP it resolves to are the same service, so results
        are also folded per port when the IP belongs to the scanned hostname.
        """
        merged: Dict[tuple, PortResult] = {}
        for item in results:
            key = (item.host, item.port)
            existing = merged.get(key)
            if existing is None:
                merged[key] = item
            elif item.version and not existing.version:
                merged[key] = item
        return sorted(merged.values(), key=lambda r: (r.host, r.port))

    # ------------------------------------------------------------------
    def scan_many(self, hosts: Iterable[str], ports: Sequence[int]) -> List[PortResult]:
        all_results: List[PortResult] = []
        for host in hosts:
            all_results.extend(self.scan_host(host, ports))
        return self._merge(all_results)


def is_web_port(port: int) -> bool:
    return port in config_mod.HTTP_PORTS or port in config_mod.HTTPS_PORTS


def is_unusual(port: int) -> bool:
    return port in UNUSUAL_PORTS


def port_severity(port: int) -> str:
    """Return 'high', 'medium' or '' for a port number."""
    if port in CRITICAL_PORTS:
        return "high"
    if port in ADMIN_PORTS:
        return "medium"
    return ""


def web_scheme(port: int) -> str:
    return "https" if port in config_mod.HTTPS_PORTS else "http"


def top_ports() -> List[int]:
    return list(config_mod.DEFAULT_PORTS)