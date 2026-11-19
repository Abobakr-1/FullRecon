"""Security-header audit.

Implements the header check from the recon roadmap without a shell loop:
collects the response headers of every live endpoint, scores the presence and
quality of each security header, and records the evidence for each verdict.

This is an observation module. A missing header is a hardening finding, not a
vulnerability, so severities stay low unless the header is actively dangerous
(for example a CSP that permits ``unsafe-inline`` or an HSTS max-age of zero).
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

from ..core.context import ModuleContext
from ..utils.helpers import dedupe, truncate

# header -> (severity when absent, rationale)
HEADER_RULES: Dict[str, Dict[str, str]] = {
    "strict-transport-security": {
        "severity": "low",
        "rationale": "HSTS forces HTTPS and blocks protocol downgrade attacks.",
        "fix": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "content-security-policy": {
        "severity": "low",
        "rationale": "CSP restricts script sources and mitigates XSS impact.",
        "fix": "Define a CSP that avoids 'unsafe-inline' and wildcard sources.",
    },
    "x-content-type-options": {
        "severity": "low",
        "rationale": "Blocks MIME sniffing that can turn an upload into script.",
        "fix": "Add: X-Content-Type-Options: nosniff",
    },
    "x-frame-options": {
        "severity": "info",
        "rationale": "Prevents framing; CSP frame-ancestors also covers this.",
        "fix": "Add: X-Frame-Options: DENY (or CSP frame-ancestors 'none').",
    },
    "referrer-policy": {
        "severity": "info",
        "rationale": "Controls how much URL data leaks to third parties.",
        "fix": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "severity": "info",
        "rationale": "Restricts powerful browser features (camera, geolocation).",
        "fix": "Add a Permissions-Policy limiting unused features.",
    },
    "cross-origin-opener-policy": {
        "severity": "info",
        "rationale": "Isolates the browsing context against cross-window attacks.",
        "fix": "Add: Cross-Origin-Opener-Policy: same-origin",
    },
}

# Headers that leak useful reconnaissance detail.
DISCLOSURE_HEADERS = {
    "server": "web server and version",
    "x-powered-by": "backend technology",
    "x-aspnet-version": "ASP.NET version",
    "x-aspnetmvc-version": "ASP.NET MVC version",
    "x-generator": "generator",
    "x-drupal-cache": "Drupal",
    "x-runtime": "Rails request timing",
    "x-version": "application version",
    "x-backend-server": "internal backend hostname",
    "x-served-by": "CDN node",
    "via": "proxy/CDN chain",
    "x-cache": "cache layer",
}

CSP_WEAK_PATTERNS = [
    (r"\bunsafe-inline\b", "CSP allows 'unsafe-inline', weakening XSS protection"),
    (r"\bunsafe-eval\b", "CSP allows 'unsafe-eval'"),
    (r"(?:\s|\*)\s*\*\s*(?:;|$)", "CSP uses a wildcard source"),
    (r"http://", "CSP mixes plaintext http:// sources"),
    (r"data:", "CSP permits data: URIs (script-injection vector)"),
]


class HeadersModule:
    name = "headers"
    label = "Security Header Audit"

    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.state = ctx.state
        self.results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    def analyse(self, url: str) -> Optional[Dict[str, Any]]:
        resp = self.ctx.http.get(url, timeout=self.ctx.cfg.timeout, read_body=False)
        if not resp.ok:
            return None

        headers = resp.headers
        missing: List[Dict[str, str]] = []
        present: Dict[str, str] = {}
        for header, rule in HEADER_RULES.items():
            value = headers.get(header, "")
            if value:
                present[header] = truncate(value, 200)
            else:
                missing.append({
                    "header": header,
                    "severity": rule["severity"],
                    "rationale": rule["rationale"],
                    "fix": rule["fix"],
                })

        weaknesses: List[str] = []
        csp = headers.get("content-security-policy", "")
        if csp:
            for pattern, message in CSP_WEAK_PATTERNS:
                if re.search(pattern, csp, re.IGNORECASE):
                    weaknesses.append(message)

        hsts = headers.get("strict-transport-security", "")
        if hsts:
            match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
            if match and int(match.group(1)) == 0:
                weaknesses.append("HSTS max-age is 0, which disables the policy")
            elif match and int(match.group(1)) < 15552000:
                weaknesses.append(
                    f"HSTS max-age {match.group(1)} is below the recommended 15552000"
                )
            if "includesubdomains" not in hsts.lower():
                weaknesses.append("HSTS does not set includeSubDomains")

        disclosures = {
            header: truncate(headers[header], 120)
            for header in DISCLOSURE_HEADERS
            if header in headers
        }

        score = max(0, len(HEADER_RULES) - len(missing))
        return {
            "url": url,
            "status": resp.status,
            "scheme": url.split("://")[0],
            "present": present,
            "missing": missing,
            "weaknesses": weaknesses,
            "disclosures": disclosures,
            "score": score,
            "max_score": len(HEADER_RULES),
        }

    # ------------------------------------------------------------------
    def run(self) -> Dict[str, object]:
        ctx = self.ctx
        urls = dedupe(ctx.state.live_urls())
        if not urls:
            ctx.warn("no live endpoints to audit for security headers")
            self._write([])
            return {"hosts": 0}

        ctx.emit(f"Auditing security headers on {len(urls)} endpoint(s)")
        with ThreadPoolExecutor(max_workers=max(1, min(ctx.cfg.threads, 20))) as pool:
            futures = {pool.submit(self.analyse, url): url for url in urls}
            for future in as_completed(futures):
                url = futures[future]
                try:
                    result = future.result()
                except Exception as exc:  # noqa: BLE001
                    ctx.record_error(self.name, f"{url}: {exc}")
                    continue
                if result:
                    self.results.append(result)

        self.results.sort(key=lambda r: r["url"])
        self.state.summary["headers"] = self.results
        self.state.header_audits = self.results
        self._write(self.results)

        weak = sum(len(r["weaknesses"]) for r in self.results)
        if self.results:
            best = max(self.results, key=lambda r: r["score"])
            ctx.emit(
                f"Headers: {len(self.results)} endpoint(s) audited, "
                f"best score {best['score']}/{best['max_score']}, {weak} weakness(es)"
            )
        return {"endpoints": len(self.results), "weaknesses": weak}

    # ------------------------------------------------------------------
    def _write(self, results: List[Dict[str, Any]]) -> None:
        out = self.ctx.out
        lines: List[str] = []
        for entry in results:
            add = lines.append
            add(f"# {entry['url']}  (score {entry['score']}/{entry['max_score']})")
            if entry["present"]:
                add("  present:")
                for header, value in sorted(entry["present"].items()):
                    add(f"    {header}: {truncate(value, 120)}")
            if entry["missing"]:
                add("  missing:")
                for item in entry["missing"]:
                    add(f"    {item['header']}  [{item['severity']}]  {item['rationale']}")
            if entry["weaknesses"]:
                add("  weaknesses:")
                for weakness in entry["weaknesses"]:
                    add(f"    - {weakness}")
            if entry["disclosures"]:
                add("  disclosures:")
                for header, value in sorted(entry["disclosures"].items()):
                    add(f"    {header}: {value}")
            add("")
        out.write("headers", "security_headers.txt", lines)

        summary = [
            f"{r['url']}\t{r['score']}/{r['max_score']}\t"
            f"{len(r['missing'])}\t{len(r['weaknesses'])}"
            for r in results
        ]
        out.write("headers", "header_scores.txt", summary)

        # A flat list of the header names most often missing, for quick triage.
        counts: Dict[str, int] = {}
        for entry in results:
            for item in entry["missing"]:
                counts[item["header"]] = counts.get(item["header"], 0) + 1
        out.write(
            "headers",
            "missing_by_frequency.txt",
            [f"{count:>4}  {header}" for header, count in
             sorted(counts.items(), key=lambda kv: -kv[1])],
        )
        out.write_json("headers", "security_headers.json", results)