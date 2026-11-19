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
        self._waf_and_cdn()
        self._security_headers()
        self._wordpress_findings()
        self._infrastructure()

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

    def _waf_and_cdn(self) -> None:
        """Report observed WAF/CDN layers as context, never as safety."""
        waf_results = (self.state.summary or {}).get("waf") or []
        if not waf_results:
            return

        behind = [r for r in waf_results if r.get("waf_detected")]
        unprotected = [r for r in waf_results if not r.get("waf_detected")]

        if behind:
            names = sorted({n for r in behind for n in r.get("signatures", [])})
            self._add(
                "Defences",
                f"{len(behind)} host(s) behind a WAF/CDN",
                INFO,
                "Blocking layers observed while probing. Their presence does not "
                "mean the application is secure; test the origin where authorized.",
                [
                    f"{r['url']}: {', '.join(r.get('signatures') or ['behavioural blocking'])}"
                    for r in behind
                ][:20],
            )
            if names:
                self._add(
                    "Defences",
                    f"WAF/CDN vendor(s): {', '.join(names[:6])}",
                    INFO,
                    "The vendor narrows which bypass techniques are worth reviewing "
                    "and whether the origin is directly reachable.",
                    names,
                )

        if unprotected:
            self._add(
                "Defences",
                f"{len(unprotected)} host(s) showed no WAF/CDN signature",
                INFO,
                "No blocking layer was observed. That is an observation about "
                "probing, not a confirmed absence of protection.",
                [r["url"] for r in unprotected][:20],
            )

    def _security_headers(self) -> None:
        """Summarise the header audit at hardening severity, not as findings."""
        audits = (self.state.summary or {}).get("headers") or []
        if not audits:
            return

        missing_hsts = [
            a["url"] for a in audits
            if a.get("scheme") == "https"
            and any(m["header"] == "strict-transport-security" for m in a["missing"])
        ]
        if missing_hsts:
            self._add(
                "Headers",
                f"HSTS missing on {len(missing_hsts)} HTTPS endpoint(s)",
                LOW,
                "Without HSTS the first request can be downgraded to plain HTTP, "
                "exposing cookies and tokens. Hardening issue, not a vulnerability "
                "on its own.",
                missing_hsts[:20],
                "https://owasp.org/www-project-secure-headers/",
            )

        unsafe_csp = [
            a["url"] for a in audits
            if any("unsafe-inline" in w or "unsafe-eval" in w
                   for w in a.get("weaknesses", []))
        ]
        if unsafe_csp:
            self._add(
                "Headers",
                f"CSP weakened by unsafe directives on {len(unsafe_csp)} endpoint(s)",
                LOW,
                "unsafe-inline/unsafe-eval reduce CSP to a weak defence against XSS. "
                "Confirm with an actual injection test before treating it as impact.",
                unsafe_csp[:20],
            )

        worst = sorted(audits, key=lambda a: a.get("score", 0))[:5]
        if worst:
            self._add(
                "Headers",
                "Security header posture summary",
                INFO,
                "Lowest-scoring endpoints first. Missing headers are hardening gaps "
                "and are only reportable with demonstrated impact.",
                [
                    "{url} scored {score}/{max_score} ({missing} missing)".format(
                        url=a["url"], score=a.get("score", 0),
                        max_score=a.get("max_score", 0),
                        missing=len(a.get("missing", [])),
                    )
                    for a in worst
                ],
            )

        disclosures: Dict[str, Set[str]] = {}
        for audit in audits:
            for header, value in (audit.get("disclosures") or {}).items():
                if header in ("server", "x-powered-by", "x-aspnet-version", "x-backend-server"):
                    disclosures.setdefault(header, set()).add(str(value))
        if disclosures:
            self._add(
                "Headers",
                "Technology/version disclosure via headers",
                LOW,
                "Banners help an attacker target known CVEs; only a finding when a "
                "specific vulnerable version is confirmed.",
                [f"{h}: {', '.join(sorted(v))[:160]}" for h, v in disclosures.items()],
            )

    def _wordpress_findings(self) -> None:
        """WordPress enumeration results, severity matched to real impact."""
        sites = (self.state.summary or {}).get("wordpress") or []
        if not sites:
            return

        versioned = [(s["url"], s.get("version")) for s in sites if s.get("version")]
        if versioned:
            self._add(
                "WordPress",
                f"WordPress version disclosed on {len(versioned)} site(s)",
                LOW,
                "The version pinpoints which plugin/core CVEs apply. Verify whether "
                "the version is actually vulnerable before reporting.",
                [f"{url}: WordPress {ver}" for url, ver in versioned],
            )

        user_enum = [s for s in sites if s.get("users")]
        if user_enum:
            self._add(
                "WordPress",
                f"User enumeration possible on {len(user_enum)} site(s)",
                LOW,
                "Valid usernames enable targeted password attacks. Enumeration alone "
                "is usually informational; pair it with a real auth weakness to report.",
                [f"{s['url']}: {', '.join(s['users'][:10])}" for s in user_enum],
            )

        xmlrpc = [s["url"] for s in sites if s.get("xmlrpc")]
        if xmlrpc:
            self._add(
                "WordPress",
                f"xmlrpc.php enabled on {len(xmlrpc)} site(s)",
                LOW,
                "xmlrpc enables amplified brute-force and pingback abuse. Only "
                "reportable with demonstrated abuse beyond rate limits.",
                xmlrpc,
            )

        backups = [
            (s["url"], path) for s in sites for path in (s.get("wp_config_backups") or [])
        ]
        if backups:
            self._add(
                "WordPress",
                "Exposed WordPress configuration file(s)",
                HIGH,
                "A readable wp-config backup leaks database credentials and salts. "
                "Confirm the response actually contains credentials before reporting.",
                [f"{url}{path}" for url, path in backups],
            )

        plugins = sorted({slug for s in sites for slug in (s.get("plugins") or [])})
        if plugins:
            self._add(
                "WordPress",
                f"{len(plugins)} WordPress plugin(s) identified",
                INFO,
                "Plugin slugs map to known CVEs. Check each version against public "
                "advisories before claiming vulnerability.",
                plugins[:40],
            )

    def _infrastructure(self) -> None:
        """Registration and ASN context from the whois and asn modules."""
        whois = (self.state.summary or {}).get("whois") or {}
        if whois and not whois.get("error"):
            details = []
            if whois.get("registrar"):
                details.append(f"registrar: {whois['registrar']}")
            events = whois.get("events") or {}
            if events.get("registration"):
                details.append(f"registered: {events['registration'][:10]}")
            if events.get("expiration"):
                details.append(f"expires: {events['expiration'][:10]}")
            if whois.get("registrant_org"):
                details.append(f"org: {whois['registrant_org']}")
            if details:
                self._add(
                    "Infrastructure",
                    "Domain registration profile",
                    INFO,
                    "Ownership and age context. A recently transferred domain is "
                    "worth checking for dangling records.",
                    details,
                )
            if not whois.get("dnssec_signed"):
                self._add(
                    "Infrastructure",
                    "DNSSEC is not enabled",
                    INFO,
                    "Without DNSSEC, DNS answers can be spoofed. Most programs treat "
                    "this as informational.",
                    [f"domain: {whois.get('domain')}"],
                )

        asn_data = (self.state.summary or {}).get("asn") or {}
        asns = asn_data.get("asns") or {}
        if asns:
            entries = []
            for asn, info in list(asns.items())[:10]:
                entries.append(
                    f"AS{asn} {info.get('holder', '')} "
                    f"({len(info.get('prefixes', []))} prefix(es))"
                )
            self._add(
                "Infrastructure",
                f"{len(asns)} announcing ASN(s) identified",
                INFO,
                "Shared hosting or cloud ranges can contain sibling assets outside "
                "the domain tree. Only test them if the program's scope allows.",
                entries,
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
