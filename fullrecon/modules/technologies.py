"""I. Technology detection from headers, cookies, HTML and asset names.

Signature based and deterministic: every match records the evidence string so
results can be audited rather than guessed.
"""

from __future__ import annotations

import json
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

from ..core import tools
from ..core.context import ModuleContext
from ..utils.helpers import dedupe, extract_html_info, truncate


def _sig(*pairs):
    """Build the standard signature table entry list."""
    return list(pairs)


# category -> list of (name, kind, pattern)
#   kind: header | cookie | body | generator | script | url
SIGNATURES: List[Tuple[str, str, str, str]] = [
    # ---- servers -----------------------------------------------------
    ("Web server", "Nginx", "header:server", r"nginx(?:/([\d.]+))?"),
    ("Web server", "Apache", "header:server", r"apache(?:/([\d.]+))?"),
    ("Web server", "IIS", "header:server", r"microsoft-iis(?:/([\d.]+))?"),
    ("Web server", "LiteSpeed", "header:server", r"litespeed"),
    ("Web server", "OpenResty", "header:server", r"openresty(?:/([\d.]+))?"),
    ("Web server", "Caddy", "header:server", r"caddy"),
    ("Web server", "Tomcat", "header:server", r"apache-coyote(?:/([\d.]+))?"),
    ("Web server", "Jetty", "header:server", r"jetty(?:\(([\d.]+)\))?"),
    ("Web server", "Gunicorn", "header:server", r"gunicorn(?:/([\d.]+))?"),
    ("Web server", "Cloudflare", "header:server", r"cloudflare"),
    ("Web server", "Envoy", "header:server", r"envoy"),
    ("Web server", "Varnish", "header:x-varnish", r".+"),
    ("Web server", "Akamai", "header:server", r"akamaighost"),
    ("Web server", "AmazonS3", "header:server", r"amazons3"),
    # ---- languages / backends ---------------------------------------
    ("Language", "PHP", "header:x-powered-by", r"php(?:/([\d.]+))?"),
    ("Language", "ASP.NET", "header:x-powered-by", r"asp\.net"),
    ("Language", "ASP.NET", "header:x-aspnet-version", r"([\d.]+)"),
    ("Language", "Express", "header:x-powered-by", r"express"),
    ("Language", "Node.js", "cookie:connect.sid", r".+"),
    # ---- frameworks ---------------------------------------------------
    ("Backend framework", "Laravel", "cookie:laravel_session", r".+"),
    ("Backend framework", "Laravel", "cookie:XSRF-TOKEN", r".+"),
    ("Backend framework", "Django", "cookie:csrftoken", r".+"),
    ("Backend framework", "Rails", "cookie:_session_id", r".+"),
    ("Backend framework", "Spring", "header:x-application-context", r".+"),
    ("Backend framework", "Next.js", "header:x-nextjs-cache", r".+"),
    ("Backend framework", "Next.js", "body", r"__NEXT_DATA__"),
    ("Backend framework", "Nuxt", "body", r"__NUXT__"),
    ("Backend framework", "Flask", "header:server", r"werkzeug(?:/([\d.]+))?"),
    # ---- frontend -----------------------------------------------------
    ("Frontend framework", "React", "body", r"data-reactroot|__REACT_DEVTOOLS|react-dom"),
    ("Frontend framework", "Vue.js", "body", r"data-v-[0-9a-f]{6,}|vue(?:\.min)?\.js"),
    ("Frontend framework", "Angular", "body", r"ng-version=|angular(?:\.min)?\.js"),
    ("Frontend framework", "Svelte", "body", r"svelte-[a-z0-9]{6,}|__sveltekit"),
    ("Frontend framework", "jQuery", "script", r"jquery[.-]?([\d.]+)?(?:\.min)?\.js"),
    ("Frontend framework", "Bootstrap", "script_or_link", r"bootstrap[.-]?([\d.]+)?"),
    ("Frontend framework", "Tailwind CSS", "body", r"tailwind"),
    # ---- CMS -----------------------------------------------------------
    ("CMS", "WordPress", "body", r"wp-content|wp-includes|/wp-json"),
    ("CMS", "WordPress", "generator", r"wordpress\s*([\d.]+)?"),
    ("CMS", "Drupal", "generator", r"drupal\s*([\d.]+)?"),
    ("CMS", "Drupal", "body", r"sites/(?:all|default)/files|Drupal\.settings"),
    ("CMS", "Joomla", "generator", r"joomla!?\s*([\d.]+)?"),
    ("CMS", "Magento", "cookie:frontend", r".+"),
    ("CMS", "Shopify", "header:x-shopid", r".+"),
    ("CMS", "Ghost", "generator", r"ghost\s*([\d.]+)?"),
    ("CMS", "TYPO3", "body", r"typo3temp|typo3conf"),
    ("CMS", "HubSpot", "header:x-hs", r".+"),
    # ---- analytics / SaaS ------------------------------------------------
    ("Analytics", "Google Analytics", "body", r"google-analytics\.com|gtag/js|googletagmanager"),
    ("Analytics", "Google Tag Manager", "body", r"googletagmanager\.com/gtm\.js"),
    ("Analytics", "Hotjar", "body", r"hotjar\.com"),
    ("Analytics", "Matomo", "body", r"matomo\.js|piwik\.js"),
    ("Analytics", "Segment", "body", r"cdn\.segment\.com"),
    ("Analytics", "Sentry", "body", r"sentry-cdn\.com|sentry\.io"),
    # ---- cloud -------------------------------------------------------------
    ("Cloud", "Amazon CloudFront", "header:x-amz-cf-id", r".+"),
    ("Cloud", "Amazon S3", "header:x-amz-request-id", r".+"),
    ("Cloud", "Azure", "header:x-azure-ref", r".+"),
    ("Cloud", "Azure Blob", "header:x-ms-blob-type", r".+"),
    ("Cloud", "Google Cloud", "header:x-goog-generation", r".+"),
    ("Cloud", "Vercel", "header:x-vercel-id", r".+"),
    ("Cloud", "Netlify", "header:x-nf-request-id", r".+"),
    ("Cloud", "Cloudflare", "header:cf-ray", r".+"),
    # ---- security / other ---------------------------------------------------
    ("Security", "HSTS", "header:strict-transport-security", r".+"),
    ("Security", "CSP", "header:content-security-policy", r".+"),
    ("Security", "AWS WAF", "cookie:aws-waf-token", r".+"),
    ("Other", "Swagger UI", "body", r"swagger-ui"),
    ("Other", "GraphiQL", "body", r"graphiql"),
    ("Other", "phpMyAdmin", "body", r"phpmyadmin"),
    ("Other", "Jenkins", "header:x-jenkins", r".+"),
]

CATEGORY_ORDER = [
    "Web server", "Language", "Backend framework", "Frontend framework", "CMS",
    "Analytics", "Cloud", "Security", "Other",
]

COMPILED = [
    (category, name, kind, re.compile(pattern, re.IGNORECASE))
    for category, name, kind, pattern in SIGNATURES
]


class TechnologyModule:
    name = "technologies"
    label = "Technology Detection"

    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.state = ctx.state

    # ------------------------------------------------------------------
    def detect(self, url: str) -> Dict[str, Dict[str, str]]:
        resp = self.ctx.http.get(url, timeout=self.ctx.cfg.timeout)
        if not resp.ok:
            return {}
        body = resp.body
        headers = resp.headers
        html_info = extract_html_info(body, url)
        linked = " ".join(html_info.get("scripts", []) + html_info.get("links", []))
        generators = " ".join(html_info.get("generators", []))

        found: Dict[str, Dict[str, str]] = {}
        for category, name, kind, regex in COMPILED:
            evidence = ""
            version = ""
            if kind.startswith("header:"):
                header_name = kind.split(":", 1)[1].lower()
                value = headers.get(header_name, "")
                match = regex.search(value) if value else None
                if match:
                    evidence = f"header {header_name}: {value[:120]}"
                    version = (match.group(1) or "") if match.groups() else ""
            elif kind.startswith("cookie:"):
                cookie_name = kind.split(":", 1)[1].lower()
                if cookie_name in resp.header("set-cookie").lower():
                    evidence = f"cookie {cookie_name}"
            elif kind == "generator":
                match = regex.search(generators)
                if match:
                    evidence = f"meta generator: {generators[:80]}"
                    version = (match.group(1) or "") if match.groups() else ""
            elif kind == "script":
                match = regex.search(linked)
                if match and ".js" in linked.lower():
                    evidence = "script reference"
                    version = ""
            elif kind == "script_or_link":
                match = regex.search(linked)
                if match:
                    evidence = "asset reference"
            else:  # body
                match = regex.search(body)
                if match:
                    evidence = f"body marker: {truncate(match.group(0), 40)}"

            if evidence:
                key = name
                entry = found.get(key, {"name": name, "category": category, "version": "", "evidence": evidence})
                if version and not entry["version"]:
                    entry["version"] = version
                found[key] = entry
        return found

    # ------------------------------------------------------------------
    def run(self) -> Dict[str, object]:
        ctx = self.ctx
        urls = ctx.state.live_urls()[:200] or [f"https://{ctx.cfg.domain}/"]
        urls = dedupe(urls)
        ctx.emit(f"Fingerprinting {len(urls)} endpoint(s)")

        per_host: Dict[str, Dict[str, Dict[str, str]]] = {}
        workers = max(1, min(ctx.cfg.threads, 20))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(self.detect, url): url for url in urls}
            for future in as_completed(futures):
                url = futures[future]
                try:
                    found = future.result()
                except Exception as exc:  # noqa: BLE001
                    ctx.record_error(self.name, f"{url}: {exc}")
                    continue
                if found:
                    host = url.split("://")[-1].split("/")[0]
                    merged = per_host.setdefault(host, {})
                    for key, entry in found.items():
                        if key not in merged or (entry.get("version") and not merged[key].get("version")):
                            merged[key] = entry

        # whatweb adds plugins and versions the header/body signatures miss.
        self._merge_whatweb(per_host, urls)

        # Aggregate for the report while keeping per-host detail.
        aggregated: Dict[str, List[Dict[str, str]]] = {}
        for host, entries in per_host.items():
            for entry in entries.values():
                bucket = aggregated.setdefault(entry["category"], [])
                if not any(e["name"] == entry["name"] for e in bucket):
                    bucket.append({"name": entry["name"], "version": entry.get("version", "")})

        self.state.technologies = aggregated
        self._write(per_host, aggregated)

        total = sum(len(v) for v in aggregated.values())
        ctx.emit(f"Technologies: {total} unique across {len(per_host)} host(s)")
        return {"technologies": total, "hosts": len(per_host)}

    # ------------------------------------------------------------------
    def _merge_whatweb(self, per_host: Dict[str, Dict[str, Dict[str, str]]],
                       urls: List[str]) -> None:
        """Fold whatweb's plugin list into the per-host technology map."""
        cfg = self.ctx.cfg
        if not (cfg.use_external_tools and tools.tool_available("whatweb")):
            return

        result = tools.whatweb(urls[:50], timeout=min(cfg.external_tool_timeout, 300.0))
        if not result.ok or not result.items:
            self.ctx.debug("whatweb produced no results")
            return

        added = 0
        for line in result.items:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            target = str(record.get("target") or "")
            host = target.split("://")[-1].split("/")[0].lower()
            if not host:
                continue
            bucket = per_host.setdefault(host, {})
            for plugin, detail in (record.get("plugins") or {}).items():
                if plugin not in bucket:
                    version = ""
                    if isinstance(detail, dict):
                        versions = detail.get("version") or []
                        if isinstance(versions, list) and versions:
                            version = str(versions[0])
                        elif versions:
                            version = str(versions)
                    bucket[plugin] = {
                        "name": plugin,
                        "category": "WhatWeb",
                        "version": version,
                        "evidence": f"whatweb plugin match on {host}",
                    }
                    added += 1
        if added:
            self.ctx.emit(f"  whatweb: {added} additional technology match(es)")

    # ------------------------------------------------------------------
    def _write(self, per_host, aggregated) -> None:
        out = self.ctx.out
        lines = []
        for category in CATEGORY_ORDER:
            entries = aggregated.get(category)
            if not entries:
                continue
            lines.append(f"[{category}]")
            for entry in sorted(entries, key=lambda e: e["name"]):
                version = f" {entry['version']}" if entry.get("version") else ""
                lines.append(f"  {entry['name']}{version}")
            lines.append("")
        out.write("technologies", "technologies.txt", lines)

        host_lines = []
        for host in sorted(per_host):
            host_lines.append(f"# {host}")
            for entry in sorted(per_host[host].values(), key=lambda e: (e["category"], e["name"])):
                version = f" {entry['version']}" if entry.get("version") else ""
                host_lines.append(f"{host}\t{entry['category']}\t{entry['name']}{version}\t{entry['evidence']}")
        out.write("technologies", "by_host.txt", host_lines)
        out.write_json("technologies", "technologies.json", {
            "aggregated": aggregated,
            "by_host": per_host,
        })