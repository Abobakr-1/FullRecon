"""WAF and CDN detection.

Two layers:

1. **Behavioural probes** — send a small number of deliberately odd requests
   (a harmless SQL-ish string, an XSS-ish string, a traversal-ish path) and look
   for blocking responses.  These are ordinary GET requests with benign
   payloads; nothing is exploited.
2. **Fingerprinting** — match response headers, cookies and block pages against
   known WAF/CDN signatures.

``wafw00f`` is used when installed, and its verdict is merged with ours.
"""

from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

from ..core import tools
from ..core.context import ModuleContext
from ..utils.helpers import dedupe, truncate

# name -> (headers that indicate it, cookie names, body markers)
SIGNATURES: List[Tuple[str, List[str], List[str], List[str]]] = [
    ("Cloudflare", ["cf-ray", "cf-cache-status", "server:cloudflare"],
     ["__cfduid", "cf_clearance"], ["cloudflare", "attention required! | cloudflare"]),
    ("Akamai", ["x-akamai-transformed", "akamai-grn", "server:akamaighost"],
     ["ak_bmsc", "bm_sz"], ["akamai", "reference&#32;&#35;"]),
    ("AWS WAF / CloudFront", ["x-amzn-requestid", "x-amz-cf-id", "x-amz-cf-pop"],
     ["aws-waf-token"], ["request blocked", "aws waf"]),
    ("Imperva / Incapsula", ["x-iinfo", "x-cdn:incapsula"],
     ["incap_ses", "visid_incap"], ["incapsula", "_incapsula_resource"]),
    ("F5 BIG-IP ASM", ["x-wa-info", "server:big-ip"],
     ["bigipserver", "ts"], ["the requested url was rejected", "big-ip"]),
    ("Sucuri", ["x-sucuri-id", "x-sucuri-cache", "server:sucuri"],
     ["sucuri_cloudproxy_uuid"], ["sucuri website firewall", "access denied - sucuri"]),
    ("ModSecurity", ["server:mod_security", "x-mod-security"],
     [], ["mod_security", "not acceptable!", "406 not acceptable"]),
    ("Barracuda", ["server:barracuda", "barra_counter_session"],
     ["barra_counter_session"], ["barracuda"]),
    ("Fortinet FortiWeb", ["server:fortiweb"], ["fortiweb"], ["fortiweb"]),
    ("Citrix NetScaler", ["via:ns-cache", "server:netscaler"],
     ["ns_af", "citrix_ns_id"], ["netscaler"]),
    ("Radware", ["server:radware"], ["rdwr"], ["radware"]),
    ("Wallarm", ["server:nginx-wallarm"], [], ["wallarm"]),
    ("Fastly CDN", ["x-fastly-request-id", "fastly-io-info", "server:fastly"],
     [], ["fastly"]),
    ("Google Cloud Armor", ["server:gws", "x-cloud-trace-context"],
     [], ["google frontend", "cloud armor"]),
    ("Azure Front Door", ["x-azure-ref", "x-fd-int-roxy-purgeid"],
     [], ["azure front door"]),
    ("Varnish", ["x-varnish", "via:varnish"], [], ["varnish"]),
    ("Nginx (no WAF)", ["server:nginx"], [], []),
]

# Benign probe payloads. These are ordinary strings, not exploit attempts.
PROBES: List[Tuple[str, str]] = [
    ("benign-baseline", ""),
    ("sql-metachar", "' OR '1'='1"),
    ("xss-metachar", "<script>alert(1)</script>"),
    ("traversal-metachar", "../../etc/passwd%00"),
]

BLOCK_STATUSES = {403, 406, 419, 429, 501, 503}


class WafModule:
    name = "waf"
    label = "WAF / CDN Detection"

    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.state = ctx.state
        self.results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    def detect_signatures(self, headers: Dict[str, str], body: str) -> List[str]:
        blob = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
        cookies = headers.get("set-cookie", "").lower()
        body_lower = (body or "")[:20000].lower()
        found: List[str] = []
        for name, header_hints, cookie_hints, body_hints in SIGNATURES:
            if any(hint in blob for hint in header_hints):
                found.append(name)
                continue
            if any(cookie in cookies for cookie in cookie_hints):
                found.append(name)
                continue
            if any(marker in body_lower for marker in body_hints):
                found.append(name)
        return dedupe(found)

    def probe(self, base_url: str) -> Dict[str, Any]:
        """Run the behavioural probe set against one host."""
        findings: Dict[str, Any] = {
            "url": base_url,
            "signatures": [],
            "behavioural": [],
            "blocked_probes": 0,
            "waf_detected": False,
            "server": "",
        }
        baseline_status: Optional[int] = None
        baseline_length = 0

        for label, payload in PROBES:
            target = base_url
            if payload:
                target = f"{base_url.rstrip('/')}/?q={quote(payload)}"
            resp = self.ctx.http.get(target, timeout=self.ctx.cfg.timeout)
            if not resp.ok:
                continue

            if label == "benign-baseline":
                baseline_status = resp.status
                baseline_length = len(resp.body)
                findings["server"] = resp.header("server")
                findings["signatures"] = self.detect_signatures(resp.headers, resp.body)
                continue

            blocked = resp.status in BLOCK_STATUSES
            # A block page is usually much shorter than the real page.
            short_page = (
                baseline_length > 0
                and len(resp.body) < max(500, baseline_length * 0.35)
            )
            if blocked or (resp.status != baseline_status and short_page):
                findings["blocked_probes"] += 1
                findings["behavioural"].append({
                    "probe": label,
                    "status": resp.status,
                    "baseline_status": baseline_status,
                    "length": len(resp.body),
                    "snippet": truncate(resp.body, 160),
                })
                signatures = self.detect_signatures(resp.headers, resp.body)
                if signatures:
                    findings["signatures"] = dedupe(findings["signatures"] + signatures)

        findings["waf_detected"] = bool(
            findings["signatures"] or findings["blocked_probes"] >= 2
        )
        return findings

    # ------------------------------------------------------------------
    def run(self) -> Dict[str, object]:
        ctx = self.ctx
        bases = self._bases()
        if not bases:
            ctx.warn("no live hosts for WAF detection")
            self._write([])
            return {"hosts": 0}

        ctx.emit(f"Fingerprinting {len(bases)} host(s) for WAF/CDN")

        with ThreadPoolExecutor(max_workers=max(1, min(ctx.cfg.threads, 10))) as pool:
            futures = {pool.submit(self.probe, base): base for base in bases}
            for future in as_completed(futures):
                base = futures[future]
                try:
                    result = future.result()
                except Exception as exc:  # noqa: BLE001
                    ctx.record_error(self.name, f"{base}: {exc}")
                    continue
                # Merge wafw00f's independent verdict when available.
                if tools.tool_available("wafw00f"):
                    waf = tools.wafw00f(base, timeout=90)
                    if waf.ok:
                        result["wafw00f"] = waf.items
                        if waf.items:
                            result["signatures"] = dedupe(
                                result["signatures"] + waf.items
                            )
                            result["waf_detected"] = True
                self.results.append(result)
                if result["waf_detected"]:
                    names = ", ".join(result["signatures"]) or "behavioural blocking"
                    ctx.emit(f"  {base:<45} WAF/CDN: {names}")

        self.results.sort(key=lambda r: r["url"])
        self.state.summary["waf"] = self.results
        self.state.waf_results = self.results
        self._write(self.results)

        detected = [r for r in self.results if r["waf_detected"]]
        ctx.emit(
            f"WAF: {len(detected)} of {len(self.results)} host(s) behind a "
            f"WAF/CDN or actively blocking probes"
        )
        return {"hosts": len(self.results), "detected": len(detected)}

    # ------------------------------------------------------------------
    def _bases(self) -> List[str]:
        from urllib.parse import urlsplit

        bases: List[str] = []
        for url in self.state.live_urls():
            parts = urlsplit(url)
            if not parts.scheme or not parts.netloc:
                continue
            base = f"{parts.scheme}://{parts.netloc}"
            if base not in bases and self.ctx.in_scope(parts.hostname or ""):
                bases.append(base)
        return bases[:10]

    def _write(self, results: List[Dict[str, Any]]) -> None:
        out = self.ctx.out
        lines = []
        for entry in results:
            verdict = "DETECTED" if entry["waf_detected"] else "not detected"
            names = ", ".join(entry["signatures"]) or "-"
            lines.append(f"{entry['url']:<50} {verdict:<12} {names}")
            if entry["server"]:
                lines.append(f"    server: {entry['server']}")
            for probe in entry["behavioural"]:
                lines.append(
                    f"    blocked probe {probe['probe']}: HTTP {probe['status']} "
                    f"(baseline {probe['baseline_status']})"
                )
            if entry.get("wafw00f"):
                lines.append(f"    wafw00f: {', '.join(entry['wafw00f'])}")
        out.write("waf", "waf_results.txt", lines)

        summary = [
            f"{r['url']}\t{'yes' if r['waf_detected'] else 'no'}\t"
            f"{','.join(r['signatures'])}\t{r['blocked_probes']}"
            for r in results
        ]
        out.write("waf", "waf_summary.txt", summary)
        out.write_json("waf", "waf.json", results)