"""Shared scan state and the per-run context handed to every module."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from ..config import Config
from ..utils.logger import Logger, get_logger
from .output_manager import OutputManager
from .scanner import HttpClient
from .scope import Scope


@dataclass
class ReconState:
    """Mutable results container shared across the pipeline."""

    target: str = ""

    # A. subdomains
    subdomains: Dict[str, List[str]] = field(default_factory=dict)  # source -> names
    resolved_subdomains: List[str] = field(default_factory=list)
    unresolved_subdomains: List[str] = field(default_factory=list)
    wildcard: Dict[str, Any] = field(default_factory=dict)

    # B. dns
    dns: Dict[str, Dict[str, List[str]]] = field(default_factory=dict)
    dangling_cnames: List[Dict[str, str]] = field(default_factory=list)
    interesting_dns: List[str] = field(default_factory=list)

    # C. live hosts
    live: List[Dict[str, Any]] = field(default_factory=list)

    # D. ports
    ports: List[Dict[str, Any]] = field(default_factory=list)
    unusual_ports: List[Dict[str, Any]] = field(default_factory=list)

    # E. urls
    urls: List[str] = field(default_factory=list)
    interesting_urls: List[str] = field(default_factory=list)
    url_sources: Dict[str, int] = field(default_factory=dict)

    # F. api
    api_endpoints: List[str] = field(default_factory=list)
    graphql_endpoints: List[str] = field(default_factory=list)
    swagger_endpoints: List[str] = field(default_factory=list)
    api_parameters: List[str] = field(default_factory=list)

    # G. javascript
    js_files: List[str] = field(default_factory=list)
    js_endpoints: List[str] = field(default_factory=list)
    js_secrets: List[Dict[str, str]] = field(default_factory=list)
    js_comments: List[Dict[str, str]] = field(default_factory=list)
    js_config_refs: List[str] = field(default_factory=list)

    # H. content discovery
    content: List[Dict[str, Any]] = field(default_factory=list)
    interesting_files: List[Dict[str, Any]] = field(default_factory=list)

    # I. technologies
    technologies: Dict[str, List[Dict[str, str]]] = field(default_factory=dict)

    # J. intelligence
    findings: List[Dict[str, Any]] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)

    # bookkeeping
    module_status: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    duration: float = 0.0

    # -- convenience ---------------------------------------------------
    def all_subdomains(self) -> List[str]:
        seen: Set[str] = set()
        out: List[str] = []
        for names in self.subdomains.values():
            for name in names:
                if name and name not in seen:
                    seen.add(name)
                    out.append(name)
        return out

    def all_hosts(self) -> List[str]:
        """Hosts to work with, most trustworthy first."""
        seen: Set[str] = set()
        out: List[str] = []
        for source in (self.resolved_subdomains, self.all_subdomains()):
            for host in source:
                if host and host not in seen:
                    seen.add(host)
                    out.append(host)
        return out

    def live_hostnames(self) -> List[str]:
        seen: Set[str] = set()
        out: List[str] = []
        for entry in self.live:
            host = entry.get("host", "")
            if host and host not in seen:
                seen.add(host)
                out.append(host)
        return out

    def live_urls(self) -> List[str]:
        seen: Set[str] = set()
        out: List[str] = []
        for entry in self.live:
            for key in ("url", "final_url"):
                url = entry.get(key, "")
                if url and url not in seen:
                    seen.add(url)
                    out.append(url)
        return out

    def counts(self) -> Dict[str, int]:
        return {
            "subdomains": len(self.all_subdomains()),
            "resolved": len(self.resolved_subdomains),
            "dns_records": sum(len(v) for v in self.dns.values()),
            "live_hosts": len({e.get("host") for e in self.live if e.get("host")}),
            "open_ports": len(self.ports),
            "technologies": len(self.technologies),
            "urls": len(self.urls),
            "api_endpoints": len(self.api_endpoints),
            "js_files": len(self.js_files),
            "js_secrets": len(self.js_secrets),
            "content_paths": len(self.content),
            "findings": len(self.findings),
        }

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "target": self.target,
            "counts": self.counts(),
            "duration_seconds": round(self.duration, 2),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "wildcard_dns": self.wildcard,
            "dns": self.dns,
            "dangling_cnames": self.dangling_cnames,
            "interesting_dns": self.interesting_dns,
            "live_hosts": self.live,
            "ports": self.ports,
            "unusual_ports": self.unusual_ports,
            "technologies": self.technologies,
            "urls": self.urls,
            "interesting_urls": self.interesting_urls,
            "api_endpoints": self.api_endpoints,
            "graphql": self.graphql_endpoints,
            "swagger": self.swagger_endpoints,
            "api_parameters": self.api_parameters,
            "javascript_files": self.js_files,
            "javascript_endpoints": self.js_endpoints,
            "javascript_secrets": self.js_secrets,
            "javascript_comments": self.js_comments,
            "content_discovery": self.content,
            "interesting_files": self.interesting_files,
            "findings": self.findings,
            "module_status": self.module_status,
            "errors": self.errors,
        }
        return data


class ModuleContext:
    """Everything a module needs: config, scope, HTTP client, output, state."""

    def __init__(
        self,
        cfg: Config,
        scope: Scope,
        http: HttpClient,
        out: OutputManager,
        state: ReconState,
        logger: Optional[Logger] = None,
        passive: bool = False,
        verbose: bool = False,
    ) -> None:
        self.cfg = cfg
        self.scope = scope
        self.http = http
        self.out = out
        self.state = state
        self.log = logger or get_logger("fullrecon")
        self.passive = passive
        self.verbose = verbose
        self._lock = threading.Lock()

    def emit(self, message: str) -> None:
        self.log.info(message)

    def debug(self, message: str, *args) -> None:
        self.log.debug(message, *args)

    def warn(self, message: str, *args) -> None:
        self.log.warning(message, *args)

    def error(self, message: str, *args) -> None:
        self.log.error(message, *args)

    def record_error(self, module: str, message: str) -> None:
        with self._lock:
            self.state.errors.append(f"{module}: {message}")

    def in_scope(self, host: str) -> bool:
        return self.scope.allows_host(host).allowed