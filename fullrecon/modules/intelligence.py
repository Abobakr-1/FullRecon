"""J. Reconnaissance intelligence: turns raw results into prioritised findings.

Scoring is transparent and rule based; nothing here exploits a target.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from ..core.context import ModuleContext
from ..core.portscan import KNOWN_SERVICES, is_unusual, is_web_port, port_severity
from ..utils.helpers import dedupe, truncate

HIGH = "high"
MEDIUM = "medium"
LOW = "low"
INFO = "info"

SEVERITY_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3}

INTERESTING_SUBDOMAIN_RE = re.compile(
    r"(?:^|\.)(?:dev|develop|development|staging|stage|stg|test|testing|qa|uat|"
    r"preprod|pre-prod|demo|sandbox|admin|internal|intranet|vpn|jenkins|gitlab|"
    r"jira|confluence|grafana|kibana|prometheus|dashboard|portal|sso|auth|"
    r"api|graphql|beta|legacy|old|backup|db|database|sql|redis|mongo|"
    r"jenkins|ci|cd|build|deploy|monitor|metrics|status|ftp|mail|smtp|"
    r"vpn|remote|proxy|gateway|edge|origin|assets|static|cdn)(?:\.|$)",
    re.IGNORECASE,
)

NOISY_FINDINGS = ("low", "info")


class IntelligenceModule:
    name = "intel"
    label = "Reconnaissance Intelligence"

    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.state = ctx.state
        self.findings: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    def _add(self, category: str, title: str, severity: str, detail: str,
             evidence: Optional[List[str]] = None, reference: str = "") -> None:
        self.findings.append({
            "category": category,
            "title": title,
            "severity": severity,
            "detail": detail,
            "evidence": list(evidence or [])[:50],
            "reference": reference,
        })

    # ------------------------------------------------------------------
    def run(self) -> Dict[str, object]:
        self._interesting_subdomains()
        self._dangling_cnames()
        self._exposed_services()
        self._unusual_ports()
        self._http_observations()
        self._interesting_endpoints()
        self._api_docs()
        self._javascript_exposure()
        self._sensitive_files()
        self._technology_notes()
        self._dns_hygiene()

        self._prioritise()
        self.state.findings = self.findings
        self._write()
        high = sum(1 for f in self.findings if f["severity"] == HIGH)
        medium = sum(1 for f in self.findings if f["severity"] == MEDIUM)
        self.ctx.emit(f"Intelligence: {len(self.findings)} finding(s) ({high} high, {medium} medium)")
        return {"findings": len(self.findings), "high": high, "medium": medium}

    # ------------------------------------------------------------------
    # Individual analyses
    # ------------------------------------------------------------------
    def _interesting_subdomains(self) -> None:
        matches = []
        for host in self.state.all_subdomains():
            if host == self.ctx.cfg.domain:
                continue
            if INTERESTING_SUBDOMAIN_RE.search(host):
                matches.append(host)
        if matches:
            severity = HIGH if any(
                re.search(r"(?:^|\.)(?:jenkins|gitlab|admin|internal|db|database|ftp|vpn)(?:\.|$)", h, re.I)
                for h in matches
            ) else MEDIUM
            self._add(
                "Subdomains",
                f"{len(matches)} high-signal subdomain(s) discovered",
                severity,
                "Subdomains whose names suggest non-production, administrative or "
                "infrastructure services. These often have weaker controls.",
                sorted(matches),
            )

        unresolved = self.state.unresolved_subdomains
        if unresolved:
            self._add(
                "Subdomains",
                f"{len(unresolved)} subdomain(s) do not resolve",
                LOW,
                "Unresolving names may be stale DNS entries. Combined with a "
                "third-party CNAME they become takeover candidates.",
                sorted(unresolved)[:50],
            )

        if self.state.wildcard.get("enabled"):
            self._add(
                "DNS",
                "Wildcard DNS is enabled",
                INFO,
                f"*.{self.ctx.cfg.domain} resolves to {self.state.wildcard.get('address')}. "
                "Brute-force results must be filtered against this to avoid false positives.",
                [str(self.state.wildcard.get("detail", ""))],
            )

    def _dangling_cnames(self) -> None:
        for item in self.state.dangling_cnames:
            self._add(
                "Subdomain takeover",
                f"Possible takeover: {item['host']}",
                HIGH,
                f"CNAME points at {item['reason']}. Verify whether the third-party "
                "resource is still claimed by the organization before reporting.",
                [f"{item['host']} -> {item['cname']}"],
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
            )

    def _exposed_services(self) -> None:
        web = []
        non_web = []
        for entry in self.state.ports:
            port = int(entry.get("port", 0))
            label = entry.get("service") or KNOWN_SERVICES.get(port, "unknown")
            description = f"{entry.get('host')}:{port} {label}"
            if entry.get("version"):
                description += f" ({entry['version']})"
            (web if is_web_port(port) or label in ("http", "https") else non_web).append(description)

        if non_web:
            self._add(
                "Services",
                f"{len(non_web)} non-web TCP service(s) exposed",
                MEDIUM,
                "Non-HTTP services reachable from the internet expand the attack "
                "surface (exposed admin planes, databases, remote access).",
                sorted(non_web)[:50],
            )

    def _unusual_ports(self) -> None:
        critical = []
        notable = []
        for entry in self.state.ports:
            port = int(entry.get("port", 0))
            label = f"{entry.get('host')}:{port} {entry.get('service', '') or KNOWN_SERVICES.get(port, '')}".strip()
            severity = port_severity(port)
            if severity == "high":
                critical.append(label)
            elif severity == "medium" or is_unusual(port):
                notable.append(label)

        if critical:
            self._add(
                "Services",
                f"{len(critical)} high-risk service(s) exposed",
                HIGH,
                "Exposed database, cache, container-API or remote-desktop services "
                "usually have no application-layer protection. Confirm whether these "
                "should be internet-facing at all.",
                sorted(critical),
            )
        if notable:
            self._add(
                "Services",
                f"{len(notable)} administrative service(s) exposed",
                MEDIUM,
                "Management and file-sharing services reachable from the internet "
                "expand the attack surface. Expected on many servers, but worth "
                "inventorying and checking for weak authentication.",
                sorted(notable),
            )

    def _http_observations(self) -> None:
        insecure = [r for r in self.state.live if r.get("scheme") == "http"]
        if insecure:
            self._add(
                "HTTP",
                f"{len(insecure)} endpoint(s) served over plain HTTP",
                MEDIUM,
                "Cleartext HTTP exposes cookies, tokens and session data to "
                "network attackers.",
                [r["url"] for r in insecure][:50],
            )

        by_host: Dict[str, List[Dict[str, Any]]] = {}
        for entry in self.state.live:
            by_host.setdefault(entry["host"], []).append(entry)
        conflicts = []
        for host, entries in by_host.items():
            urls = {e["url"].split("://")[0] for e in entries}
            if {"http", "https"} <= urls:
                conflicts.append(host)
        if conflicts:
            self._add(
                "HTTP",
                f"{len(conflicts)} host(s) answer on both HTTP and HTTPS",
                LOW,
                "Content served on both schemes can bypass HSTS-only protections "
                "and cause mixed-content or cache issues.",
                conflicts,
            )

        errors = [r for r in self.state.live if 500 <= int(r.get("status", 0)) < 600]
        if errors:
            self._add(
                "HTTP",
                f"{len(errors)} endpoint(s) return 5xx errors",
                INFO,
                "Server errors can disclose stack traces, framework versions and "
                "internal hostnames.",
                [f"{r['url']} -> {r['status']}" for r in errors][:30],
            )

    def _interesting_endpoints(self) -> None:
        urls = self.state.interesting_urls or []
        if not urls:
            return
        param_urls = [u for u in urls if "?" in u]
        self._add(
            "URLs",
            f"{len(urls)} interesting URL(s) collected",
            MEDIUM if param_urls else LOW,
            "URLs matching sensitive keywords/extensions or carrying query "
            "parameters are prime candidates for manual review.",
            sorted(urls)[:50],
        )

    def _api_docs(self) -> None:
        docs = dedupe(self.state.swagger_endpoints + self.state.graphql_endpoints)
        if docs:
            self._add(
                "API",
                f"{len(docs)} API documentation/console surface(s)",
                HIGH,
                "OpenAPI/Swagger/GraphQL interfaces describe every operation and "
                "parameter. Documentation exposure itself is not a vulnerability, "
                "but it accelerates review of authentication and authorization.",
                sorted(docs)[:30],
            )
        if self.state.api_endpoints:
            self._add(
                "API",
                f"{len(self.state.api_endpoints)} API endpoint(s) mapped",
                INFO,
                "Endpoints harvested from URLs, JavaScript and documentation.",
                sorted(self.state.api_endpoints)[:50],
            )

    def _javascript_exposure(self) -> None:
        high = [s for s in self.state.js_secrets if s.get("confidence") == HIGH]
        medium = [s for s in self.state.js_secrets if s.get("confidence") == MEDIUM]
        if high or medium:
            self._add(
                "JavaScript",
                f"{len(high) + len(medium)} potential secret(s) referenced in JavaScript",
                HIGH if high else MEDIUM,
                "Values are redacted and were NOT used. Confirm whether the key is "
                "live and report through the program channel; never test credentials.",
                [
                    f"{s['type']} ({s['confidence']}) {s['value_redacted']} in {s['source']}"
                    for s in (high + medium)[:30]
                ],
            )
        if self.state.js_comments:
            self._add(
                "JavaScript",
                f"{len(self.state.js_comments)} sensitive comment(s) in JavaScript",
                LOW,
                "Developer comments can reveal internal paths, TODOs about "
                "security controls, or leftover debug logic.",
                [f"{c['source']}: {c['comment'][:120]}" for c in self.state.js_comments[:30]],
            )
        if self.state.js_endpoints:
            self._add(
                "JavaScript",
                f"{len(self.state.js_endpoints)} endpoint(s) extracted from JavaScript",
                INFO,
                "Client-side bundles frequently reveal private API routes.",
                sorted(self.state.js_endpoints)[:50],
            )

    def _sensitive_files(self) -> None:
        files = self.state.interesting_files or []
        if not files:
            return
        risky = [
            f for f in files
            if any(token in str(f.get("url", "")).lower() for token in (
                ".env", ".git/", ".sql", ".bak", ".zip", ".tar", "config", "backup",
                "dump", "actuator/env", "phpinfo", "credentials",
            ))
        ]
        if risky:
            self._add(
                "Content",
                f"{len(risky)} sensitive file/path(s) accessible",
                HIGH,
                "Exposed configuration, backup or debug files can leak credentials, "
                "source code or internal topology.",
                [str(f.get("url")) for f in risky][:40],
            )
        if len(files) > len(risky):
            self._add(
                "Content",
                f"{len(files)} interesting path(s) discovered",
                LOW,
                "Paths that are accessible and worth a manual look.",
                [str(f.get("url")) for f in files][:50],
            )

    def _technology_notes(self) -> None:
        tech = self.state.technologies
        if not tech:
            return
        names = {t["name"] for group in tech.values() for t in group}
        outdated = sorted(t["name"] + (f" {t['version']}" if t.get("version") else "")
                          for group in tech.values() for t in group if t.get("version"))
        if outdated:
            self._add(
                "Technologies",
                f"{len(outdated)} technology version(s) disclosed",
                LOW,
                "Banner/version disclosure helps attackers target known CVEs. "
                "Version numbers here come from public responses only.",
                outdated[:40],
            )
        if {"WordPress", "Drupal", "Joomla"} & names:
            self._add(
                "Technologies",
                "CMS detected",
                INFO,
                "CMS platforms have large plugin/theme attack surfaces. Enumerate "
                "extensions manually with authorization.",
                sorted({"WordPress", "Drupal", "Joomla"} & names),
            )

    def _dns_hygiene(self) -> None:
        if not self.state.dns:
            # No DNS data collected (module skipped or failed): saying "no SPF"
            # would be a claim we cannot support.
            return
        txt = self.state.dns.get(self.ctx.cfg.domain, {}).get("TXT", [])
        joined = " ".join(txt).lower()
        if txt and "v=spf1" not in joined:
            self._add(
                "DNS",
                "No SPF record on the apex domain",
                LOW,
                "Without SPF (and DMARC), the domain can be spoofed in email.",
                txt[:10],
            )
        elif "v=spf1" in joined and "+all" in joined:
            self._add(
                "DNS",
                "Permissive SPF record (+all)",
                MEDIUM,
                "SPF ending in +all authorises any host to send mail as the domain.",
                [t for t in txt if "v=spf1" in t.lower()][:5],
            )
        if txt and not any("v=dmarc1" in t.lower() for t in txt):
            dmarc = self.state.dns.get(f"_dmarc.{self.ctx.cfg.domain}", {}).get("TXT", [])
            if not any("v=dmarc1" in t.lower() for t in dmarc):
                self._add(
                    "DNS",
                    "No DMARC record found",
                    INFO,
                    "DMARC is required by many programs and mail providers; its "
                    "absence weakens anti-spoofing posture.",
                )

    # ------------------------------------------------------------------
    def _prioritise(self) -> None:
        self.findings.sort(
            key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["category"], f["title"])
        )

    def _write(self) -> None:
        out = self.ctx.out
        lines: List[str] = []
        current = None
        for finding in self.findings:
            if finding["severity"] != current:
                current = finding["severity"]
                lines.append("")
                lines.append(f"=== {current.upper()} ===")
                lines.append("")
            lines.append(f"[{finding['category']}] {finding['title']}")
            lines.append(f"  {finding['detail']}")
            for item in finding["evidence"][:10]:
                lines.append(f"    - {truncate(str(item), 160)}")
            if finding.get("reference"):
                lines.append(f"    ref: {finding['reference']}")
            lines.append("")
        out.write("reports", "findings.txt", lines)

        summary = {
            "target": self.ctx.cfg.domain,
            "generated": self.state.finished_at or self.state.started_at,
            "counts": self.state.counts(),
            "severity": {
                level: sum(1 for f in self.findings if f["severity"] == level)
                for level in (HIGH, MEDIUM, LOW, INFO)
            },
            "findings": self.findings,
            "next_steps": [
                "Manually verify each high-severity finding before reporting.",
                "Do not test discovered credentials or bypass access controls.",
                "Check the program's scope and rules for every host you touched.",
            ],
        }
        out.write_json("reports", "findings.json", summary)