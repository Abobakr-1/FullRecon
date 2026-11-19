"""Port scanning module (module wrapper around core.portscan)."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List

from ..core.context import ModuleContext
from ..core.portscan import (
    KNOWN_SERVICES,
    PortScanner,
    is_unusual,
    is_web_port,
)


class PortScanModule:
    name = "ports"
    label = "Port Scanning"

    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.state = ctx.state
        self.scanner = PortScanner(ctx.cfg, ctx.scope, ctx.log)

    # ------------------------------------------------------------------
    def run(self) -> Dict[str, object]:
        cfg = self.ctx.cfg
        hosts = self._targets()
        ports = self._ports()
        if not hosts:
            self.ctx.warn("no in-scope hosts to scan")
            return {"hosts": 0}
        if not ports:
            self.ctx.warn("no ports selected for scanning")
            return {"hosts": 0}

        self.ctx.emit(
            f"Scanning {len(hosts)} host(s) x {len(ports)} port(s) "
            f"({'nmap service detection' if cfg.use_nmap else 'TCP connect'})"
        )

        results = []
        for index, host in enumerate(hosts, start=1):
            if self.ctx.passive:
                break
            found = self.scanner.scan_host(host, ports)
            if found:
                results.extend(found)
                self.ctx.emit(
                    "  {host:<40} {count} open: {ports}".format(
                        host=host, count=len(found),
                        ports=",".join(str(r.port) for r in found[:12]),
                    )
                )
            else:
                self.ctx.debug("  %s: no open ports found", host)

        merged = PortScanner._merge(results)
        entries = []
        for item in merged:
            entry = item.to_dict()
            entry["web"] = is_web_port(item.port)
            entry["unusual"] = is_unusual(item.port)
            entries.append(entry)

        self.state.ports = entries
        self.state.unusual_ports = [e for e in entries if e["unusual"]]
        self._write(entries)

        open_hosts = len({e["host"] for e in entries})
        self.ctx.emit(f"Ports: {len(entries)} open port(s) across {open_hosts} host(s)")
        if self.state.unusual_ports:
            self.ctx.warn(
                f"{len(self.state.unusual_ports)} sensitive port(s) reachable "
                f"(e.g. {self.state.unusual_ports[0]['port']})"
            )
        return {"open_ports": len(entries), "hosts": open_hosts}

    # ------------------------------------------------------------------
    def _targets(self) -> List[str]:
        hosts = self.state.resolved_subdomains or self.state.all_hosts()
        hosts = [h for h in hosts if self.ctx.in_scope(h)]
        if self.ctx.cfg.domain not in hosts:
            hosts.insert(0, self.ctx.cfg.domain)
        # Port scanning every subdomain on a large scope is slow and impolite.
        limit = max(1, min(len(hosts), 50))
        if len(hosts) > limit:
            self.ctx.warn(f"port scanning first {limit} host(s) of {len(hosts)}")
        return hosts[:limit]

    def _ports(self) -> List[int]:
        cfg = self.ctx.cfg
        if not cfg.ports:
            from ..config import DEFAULT_PORTS

            return list(DEFAULT_PORTS)
        return sorted({int(p) for p in cfg.ports if 0 < int(p) < 65536})

    # ------------------------------------------------------------------
    def _write(self, entries: List[Dict[str, object]]) -> None:
        out = self.ctx.out
        out.write("ports", "open_ports.txt", [
            f"{e['host']}:{e['port']}" for e in entries
        ])
        out.write("ports", "services.txt", [
            "{host}:{port} {service}{version}".format(
                host=e["host"], port=e["port"], service=e.get("service") or "unknown",
                version=f" ({e['version']})" if e.get("version") else "",
            )
            for e in entries
        ])
        out.write("ports", "web_ports.txt", [
            f"{e['host']}:{e['port']}" for e in entries if e.get("web")
        ])
        out.write("ports", "unusual_ports.txt", [
            f"{e['host']}:{e['port']} {e.get('service', '')}".strip()
            for e in entries if e.get("unusual")
        ])
        out.write_json("ports", "ports.json", entries)

        by_host: Dict[str, List[Dict[str, object]]] = {}
        for entry in entries:
            by_host.setdefault(str(entry["host"]), []).append(entry)
        out.write_json("ports", "ports_by_host.json", by_host)