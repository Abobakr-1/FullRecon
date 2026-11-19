"""C. Live host discovery: HTTP/HTTPS probing, titles, redirects, servers."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

from ..core.context import ModuleContext
from ..core.portscan import KNOWN_SERVICES, is_web_port, web_scheme
from ..utils.helpers import dedupe, truncate
from ..utils.validators import is_ip


class LiveHostModule:
    name = "live"
    label = "Live Host Discovery"

    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.state = ctx.state

    # ------------------------------------------------------------------
    def _candidates(self) -> List[Tuple[str, str]]:
        """Build (scheme, host:port) probe targets from earlier results."""
        seen = set()
        targets: List[Tuple[str, str]] = []

        # Only DNS-validated hosts are worth an HTTP probe; unresolved names
        # would burn one timeout each for no information.
        hosts = self.state.resolved_subdomains or self.state.all_hosts()
        if self.ctx.cfg.domain not in hosts:
            hosts = [self.ctx.cfg.domain] + list(hosts)
        if not hosts:
            hosts = [self.ctx.cfg.domain]
        for host in hosts:
            if not self.ctx.in_scope(host):
                continue
            for scheme in ("https", "http"):
                key = (scheme, host)
                if key not in seen:
                    seen.add(key)
                    targets.append((scheme, host))

        # Web ports discovered during port scanning (run order permitting).
        for entry in self.state.ports:
            port = int(entry.get("port", 0))
            host = entry.get("host", "")
            if not host or not is_web_port(port):
                continue
            scheme = web_scheme(port)
            key = (scheme, f"{host}:{port}")
            if key not in seen and self.ctx.in_scope(host):
                seen.add(key)
                targets.append((scheme, f"{host}:{port}"))
        return targets

    @staticmethod
    def _display_target(scheme: str, hostport: str) -> str:
        """Drop a port that is already implied by the scheme."""
        host, _, port = hostport.partition(":")
        if port and ((scheme == "http" and port == "80") or (scheme == "https" and port == "443")):
            return host
        return hostport

    def _probe(self, scheme: str, hostport: str) -> Optional[Dict[str, object]]:
        url = f"{scheme}://{self._display_target(scheme, hostport)}/"
        resp = self.ctx.http.get(url, timeout=self.ctx.cfg.timeout)
        if not resp.ok:
            return None
        if resp.status >= 500 and not self.ctx.cfg.verify_status:
            return None

        host = hostport.split(":")[0]
        final_url = resp.redirect_chain[-1] if resp.redirect_chain else url
        entry = {
            "host": host,
            "url": url,
            "final_url": final_url,
            "scheme": scheme,
            "status": resp.status,
            "title": truncate(resp.title, 120),
            "server": resp.header("server"),
            "powered_by": resp.header("x-powered-by"),
            "content_type": resp.header("content-type"),
            "redirect": resp.header("location"),
            "content_length": len(resp.body),
            "elapsed": round(resp.elapsed, 3),
            "port": int(hostport.split(":")[1]) if ":" in hostport else (443 if scheme == "https" else 80),
        }
        return entry

    # ------------------------------------------------------------------
    def run(self) -> Dict[str, object]:
        ctx = self.ctx
        cfg = ctx.cfg
        candidates = self._candidates()
        if not candidates:
            ctx.warn("no candidate hosts for live discovery")
            return {"live": 0}

        limit = cfg.max_live_hosts
        if len(candidates) > limit:
            ctx.warn(f"limiting live-host probes to {limit} targets (of {len(candidates)})")
            candidates = candidates[:limit]

        ctx.emit(f"Probing {len(candidates)} host/scheme combination(s)")
        results: List[Dict[str, object]] = []
        workers = max(1, min(cfg.threads, 40))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(self._probe, scheme, hostport): (scheme, hostport)
                       for scheme, hostport in candidates}
            for future in as_completed(futures):
                scheme, hostport = futures[future]
                try:
                    entry = future.result()
                except Exception as exc:  # noqa: BLE001
                    ctx.record_error(self.name, f"{hostport}: {exc}")
                    continue
                if entry:
                    results.append(entry)
                    ctx.debug("live: %s://%s %s", scheme, hostport, entry["status"])

        # The same endpoint can be probed twice (default port from the port
        # scanner plus the scheme-implied one). Keep a single record, preferring
        # the lowest status code.
        deduped: Dict[tuple, Dict[str, object]] = {}
        for entry in results:
            key = (entry["host"], entry["scheme"], entry["port"])
            if key not in deduped or entry["status"] < deduped[key]["status"]:
                deduped[key] = entry
        results = sorted(deduped.values(), key=lambda e: (e["host"], e["port"]))
        self.state.live = results
        self._write(results)

        hosts = len({r["host"] for r in results})
        ctx.emit(f"Live hosts: {hosts} host(s), {len(results)} endpoint(s) responding")
        return {"live_hosts": hosts, "endpoints": len(results)}

    # ------------------------------------------------------------------
    def _write(self, results: List[Dict[str, object]]) -> None:
        out = self.ctx.out
        live_hosts = dedupe([f"{r['host']}" for r in results])
        http_hosts = dedupe([r["url"] for r in results if r["scheme"] == "http"])
        https_hosts = dedupe([r["url"] for r in results if r["scheme"] == "https"])

        out.write("live", "live_hosts.txt", live_hosts)
        out.write("live", "http_hosts.txt", http_hosts)
        out.write("live", "https_hosts.txt", https_hosts)

        detail_lines = []
        for r in results:
            redirect = f" -> {r['redirect']}" if r.get("redirect") else ""
            detail_lines.append(
                "{host:<40} {status:<4} {url:<45} [{server}] {title}{redirect}".format(
                    host=r["host"], status=r["status"], url=r["url"],
                    server=r.get("server") or "-", title=r.get("title") or "",
                    redirect=redirect,
                ).rstrip()
            )
        out.write("live", "host_details.txt", detail_lines)

        # Simple URLs list used by later modules.
        out.write("live", "live_urls.txt", dedupe([r["final_url"] for r in results]))
        out.write_json("live", "live_hosts.json", results)
        out.write_raw("live_probe.json", [json.dumps(r, default=str) for r in results])