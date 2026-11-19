"""Scope enforcement: decides which hosts/ports FullRecon may touch.

Every network-touching module calls :class:`Scope` before sending traffic.
An empty ``in_scope`` list means "the target domain and its subdomains".
"""

from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass, field
from typing import Iterable, List, Optional

from ..utils.helpers import dedupe, read_lines
from ..utils.validators import in_domain, is_ip, normalise_target


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str = ""

    def __bool__(self) -> bool:  # pragma: no cover - convenience
        return self.allowed


class Scope:
    """Allow/deny evaluator with wildcard and CIDR support."""

    def __init__(
        self,
        domain: str,
        in_scope: Optional[Iterable[str]] = None,
        out_of_scope: Optional[Iterable[str]] = None,
        allowed_ports: Optional[Iterable[int]] = None,
        scope_file: Optional[str] = None,
    ) -> None:
        self.domain = normalise_target(domain)
        self.in_scope: List[str] = []
        self.out_of_scope: List[str] = []
        self.networks: List[ipaddress._BaseNetwork] = []
        self.allowed_ports = sorted({int(p) for p in (allowed_ports or [])})

        entries = list(in_scope or [])
        if scope_file:
            entries.extend(self._parse_scope_file(scope_file))
        for entry in entries:
            self._add(entry, include=True)
        for entry in out_of_scope or []:
            self._add(entry, include=False)

        # The primary target is always in scope.
        if not self.in_scope:
            self.in_scope.append(self.domain)

    # ------------------------------------------------------------------
    @staticmethod
    def _parse_scope_file(path: str) -> List[str]:
        lines = []
        for line in read_lines(path):
            if line.startswith("#") or line.startswith("//"):
                continue
            lines.append(line)
        return lines

    def _add(self, entry: str, include: bool) -> None:
        entry = (entry or "").strip()
        if not entry:
            return
        lowered = entry.lower()
        if lowered.startswith("!") or lowered.startswith("-"):
            entry, include = entry[1:].strip(), False
        if "/" in entry and _is_network(entry):
            try:
                self.networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                pass
            return
        if lowered.startswith("*."):
            entry = entry[2:]
        try:
            entry = normalise_target(entry)
        except ValueError:
            return
        bucket = self.in_scope if include else self.out_of_scope
        if entry not in bucket:
            bucket.append(entry)

    # ------------------------------------------------------------------
    def allows_host(self, host: str) -> ScopeDecision:
        host = (host or "").strip().lower().rstrip(".")
        if not host:
            return ScopeDecision(False, "empty host")

        for denied in self.out_of_scope:
            if self._matches(host, denied):
                return ScopeDecision(False, f"excluded by out-of-scope rule {denied!r}")

        if self._matches(host, self.domain):
            return ScopeDecision(True)

        for allowed in self.in_scope:
            if self._matches(host, allowed):
                if is_ip(host) and self._ip_excluded(host):
                    return ScopeDecision(False, "IP inside excluded network")
                return ScopeDecision(True)

        if is_ip(host):
            for network in self.networks:
                try:
                    if ipaddress.ip_address(host) in network:
                        return ScopeDecision(True)
                except ValueError:
                    continue

        return ScopeDecision(False, f"{host} is outside the configured scope")

    def allows_url(self, url: str) -> ScopeDecision:
        from urllib.parse import urlsplit

        try:
            parts = urlsplit(url)
        except ValueError:
            return ScopeDecision(False, "malformed URL")
        if parts.scheme not in ("http", "https"):
            return ScopeDecision(False, f"unsupported scheme {parts.scheme!r}")
        if not parts.hostname:
            return ScopeDecision(False, "URL has no host")
        decision = self.allows_host(parts.hostname)
        if not decision.allowed:
            return decision
        port = parts.port or (443 if parts.scheme == "https" else 80)
        return self.allows_port(port)

    def allows_port(self, port: int) -> ScopeDecision:
        if self.allowed_ports and int(port) not in self.allowed_ports:
            return ScopeDecision(False, f"port {port} not in allowed port list")
        return ScopeDecision(True)

    # ------------------------------------------------------------------
    def _ip_excluded(self, host: str) -> bool:
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            return False
        for network in self.networks:
            if addr in network:
                return True
        return False

    @staticmethod
    def _matches(host: str, pattern: str) -> bool:
        if not pattern:
            return False
        if pattern == host:
            return True
        if in_domain(host, pattern):
            return True
        if "*" in pattern or "?" in pattern or "[" in pattern:
            return fnmatch.fnmatch(host, pattern)
        return False

    # ------------------------------------------------------------------
    def filter_hosts(self, hosts: Iterable[str]) -> List[str]:
        seen = set()
        out = []
        for host in hosts:
            host = (host or "").strip().lower().rstrip(".")
            if not host or host in seen:
                continue
            if self.allows_host(host):
                seen.add(host)
                out.append(host)
        return out

    def describe(self) -> str:
        lines = [f"primary target : {self.domain}"]
        lines.append(f"in scope       : {', '.join(self.in_scope) or '(primary only)'}")
        if self.out_of_scope:
            lines.append(f"out of scope   : {', '.join(self.out_of_scope)}")
        if self.allowed_ports:
            lines.append(f"allowed ports  : {', '.join(map(str, self.allowed_ports))}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "in_scope": self.in_scope,
            "out_of_scope": self.out_of_scope,
            "allowed_ports": self.allowed_ports,
            "networks": [str(n) for n in self.networks],
        }


def _is_network(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False