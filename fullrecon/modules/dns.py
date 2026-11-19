"""B. DNS enumeration: records, dangling CNAME detection, interesting records."""

from __future__ import annotations

import json
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Iterable, List, Optional, Tuple

from ..core.context import ModuleContext
from ..utils.helpers import dedupe, read_lines, write_lines
from ..utils.validators import in_domain, is_ip

try:  # pragma: no cover - dependency is optional at import time
    import dns.exception  # type: ignore
    import dns.resolver  # type: ignore
    import dns.rdatatype  # type: ignore
    _HAS_DNSPYTHON = True
except Exception:  # pragma: no cover
    dns = None  # type: ignore
    _HAS_DNSPYTHON = False

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "PTR")

# Hostnames that betray third-party hosting. A CNAME pointing at one of these
# that no longer resolves is a classic subdomain-takeover candidate.
TAKEOVER_FINGERPRINTS = {
    "s3.amazonaws.com": "S3 bucket",
    "s3-website": "S3 website",
    "cloudfront.net": "CloudFront",
    "herokuapp.com": "Heroku",
    "herokudns.com": "Heroku",
    "github.io": "GitHub Pages",
    "azurewebsites.net": "Azure App Service",
    "cloudapp.azure.com": "Azure VM",
    "trafficmanager.net": "Azure Traffic Manager",
    "blob.core.windows.net": "Azure Blob",
    "azureedge.net": "Azure CDN",
    "elasticbeanstalk.com": "AWS Elastic Beanstalk",
    "cargocollective.com": "Cargo",
    "unbouncepages.com": "Unbounce",
    "statuspage.io": "Statuspage",
    "readthedocs.io": "Read the Docs",
    "ghost.io": "Ghost",
    "myshopify.com": "Shopify",
    "zendesk.com": "Zendesk",
    "heroes.com": "Heroku",
    "desk.com": "Desk",
    "bitbucket.io": "Bitbucket",
    "wordpress.com": "WordPress.com",
    "teamwork.com": "Teamwork",
    "surveymonkey.com": "SurveyMonkey",
    "fastly.net": "Fastly",
    "pantheonsite.io": "Pantheon",
    "aftership.com": "AfterShip",
    "brightcove.com": "Brightcove",
    "wixsite.com": "Wix",
    "netlify.app": "Netlify",
    "vercel.app": "Vercel",
    "fly.dev": "Fly.io",
}

SPF_RE = re.compile(r"v=spf1", re.IGNORECASE)
DMARC_HINT = "_dmarc"
DKIM_HINT = "_domainkey"
DNS_SECURITY_HINTS = ("v=spf1", "v=dmarc1", "v=dkim1", "include:", "-all", "~all")


class DnsModule:
    name = "dns"
    label = "DNS Enumeration"

    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.state = ctx.state
        self.resolver = self._build_resolver()

    # ------------------------------------------------------------------
    def _build_resolver(self):
        if not _HAS_DNSPYTHON:
            return None
        resolver = dns.resolver.Resolver(configure=True)
        if self.ctx.cfg.dns_resolvers:
            resolver.nameservers = list(self.ctx.cfg.dns_resolvers)
        resolver.lifetime = 4
        resolver.timeout = 2
        return resolver

    def _query(self, name: str, rtype: str) -> List[str]:
        if self.resolver is not None:
            try:
                answers = self.resolver.resolve(name, rtype, raise_on_no_answer=False)
                if answers.rrset is None:
                    return []
                out = []
                for record in answers:
                    text = record.to_text().rstrip(".")
                    if rtype == "MX":
                        text = text.split()[-1].rstrip(".")
                    out.append(text.strip('"'))
                return dedupe(out)
            except Exception:
                return []
        return self._query_stdlib(name, rtype)

    def _query_stdlib(self, name: str, rtype: str) -> List[str]:
        """Minimal fallback using dnspython-free socket calls."""
        if rtype == "A":
            try:
                return dedupe(socket.gethostbyname_ex(name)[2])
            except (socket.gaierror, UnicodeError):
                return []
        if rtype == "AAAA":
            try:
                infos = socket.getaddrinfo(name, None, socket.AF_INET6)
                return dedupe({i[4][0] for i in infos})
            except (socket.gaierror, UnicodeError):
                return []
        return []

    # ------------------------------------------------------------------
    def enumerate_domain(self, domain: str) -> Dict[str, List[str]]:
        records: Dict[str, List[str]] = {}
        for rtype in RECORD_TYPES:
            values = self._query(domain, rtype)
            if values:
                records[rtype] = values
        # Common security-relevant TXT records live on fixed labels.
        for label in (f"{DMARC_HINT}.{domain}", f"default.{DKIM_HINT}.{domain}"):
            values = self._query(label, "TXT")
            if values:
                records.setdefault("TXT", [])
                for value in values:
                    entry = f"{label} {value}"
                    if entry not in records["TXT"]:
                        records["TXT"].append(entry)
        return records

    def enumerate_host(self, host: str) -> Dict[str, List[str]]:
        records = self.enumerate_domain(host)
        if "SOA" in records and host != self.ctx.cfg.domain:
            # SOA on a subdomain is almost always inherited; drop it.
            records.pop("SOA", None)
        return records

    # ------------------------------------------------------------------
    def run(self) -> Dict[str, object]:
        ctx = self.ctx
        cfg = ctx.cfg
        target = cfg.domain

        if not _HAS_DNSPYTHON:
            ctx.warn("dnspython is not installed - using reduced DNS resolution")

        # Only hosts that already resolve are worth a full record lookup;
        # unresolved names have no A/AAAA/CNAME by definition.
        candidates = self.state.resolved_subdomains or self.state.all_hosts()
        hosts = [h for h in candidates if ctx.in_scope(h)]
        if not hosts:
            hosts = [target]
        # Always include the apex even if it did not appear in subdomain results.
        if target not in hosts:
            hosts.insert(0, target)

        ctx.emit(f"Enumerating DNS records for {len(hosts)} host(s)")

        records_by_host: Dict[str, Dict[str, List[str]]] = {}
        workers = max(1, min(cfg.dns_threads, 32))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(self.enumerate_host, host): host for host in hosts}
            for future in as_completed(futures):
                host = futures[future]
                try:
                    records = future.result()
                except Exception as exc:  # noqa: BLE001
                    ctx.record_error(self.name, f"{host}: {exc}")
                    continue
                if records:
                    records_by_host[host] = records

        # Anything that resolves now counts as a resolved hostname.
        resolved = [h for h, recs in records_by_host.items() if recs.get("A") or recs.get("AAAA") or recs.get("CNAME")]
        unresolved = [h for h in hosts if h not in resolved and h != target]
        self.state.dns = records_by_host
        self.state.resolved_subdomains = dedupe(resolved + self.state.resolved_subdomains)
        self.state.unresolved_subdomains = dedupe(unresolved + self.state.unresolved_subdomains)

        cname_lines: List[str] = []
        dangling: List[Dict[str, str]] = []
        interesting: List[str] = []

        for host, recs in records_by_host.items():
            for cname in recs.get("CNAME", []):
                cname_lines.append(f"{host} -> {cname}")
                reason = self._takeover_reason(cname)
                if reason:
                    dangling.append({"host": host, "cname": cname, "reason": reason})
            for txt in recs.get("TXT", []):
                if any(hint in txt.lower() for hint in DNS_SECURITY_HINTS):
                    interesting.append(f"TXT {host}: {txt[:250]}")
            for mx in recs.get("MX", []):
                interesting.append(f"MX  {host}: {mx}")
            for ns in recs.get("NS", []):
                interesting.append(f"NS  {host}: {ns}")
            if "CAA" in recs:
                interesting.append(f"CAA {host}: {', '.join(recs['CAA'])}")
            if "SOA" in recs:
                interesting.append(f"SOA {host}: {', '.join(recs['SOA'])}")

        self.state.dangling_cnames = dangling
        self.state.interesting_dns = dedupe(interesting)

        self._write(records_by_host, cname_lines, dangling, interesting)

        if dangling:
            ctx.warn(f"{len(dangling)} CNAME(s) point at unclaimed third-party services")
        ctx.emit(
            f"DNS: {len(records_by_host)} hosts, "
            f"{sum(len(v) for v in records_by_host.values())} records, "
            f"{len(dangling)} dangling CNAME(s)"
        )
        return {
            "hosts": len(records_by_host),
            "records": sum(len(v) for v in records_by_host.values()),
            "dangling": len(dangling),
        }

    # ------------------------------------------------------------------
    @staticmethod
    def _takeover_reason(cname: str) -> str:
        lowered = (cname or "").lower().rstrip(".")
        for fingerprint, service in TAKEOVER_FINGERPRINTS.items():
            if lowered.endswith(fingerprint) or f".{fingerprint}" in lowered:
                return f"points at {service} ({fingerprint})"
        return ""

    def _write(self, records_by_host, cname_lines, dangling, interesting) -> None:
        out = self.ctx.out
        lines: List[str] = []
        for host in sorted(records_by_host):
            lines.append(f"# {host}")
            for rtype, values in records_by_host[host].items():
                for value in values:
                    lines.append(f"{host}\t{rtype}\t{value}")
            lines.append("")
        out.write("dns", "dns_records.txt", lines)
        out.write("dns", "cname_records.txt", sorted(cname_lines))
        out.write("dns", "interesting_dns.txt", sorted(interesting))

        dangling_lines = [
            f"{d['host']} -> {d['cname']}  [{d['reason']}]" for d in dangling
        ]
        out.write("dns", "dangling_cnames.txt", dangling_lines)

        json_records = {
            host: {rtype: values for rtype, values in recs.items()}
            for host, recs in records_by_host.items()
        }
        out.write_json("dns", "dns_records.json", json_records)
        out.write_raw("dns_nslookup.txt", _raw_lookup(records_by_host))


def _raw_lookup(records_by_host) -> List[str]:
    lines = []
    for host in sorted(records_by_host):
        for rtype, values in records_by_host[host].items():
            lines.append(f"{host} {rtype} {' '.join(values)}")
    return lines


__all__ = ["DnsModule", "TAKEOVER_FINGERPRINTS", "RECORD_TYPES"]