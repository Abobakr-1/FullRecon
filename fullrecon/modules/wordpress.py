"""WordPress enumeration — only runs when WordPress is actually detected.

Implements the ``wpscan --enumerate vp,vt,u`` workflow without requiring the
Ruby wpscan binary:

* version        — from meta generator, readme.html, feed generator
* plugins        — from ``/wp-content/plugins/<slug>/`` references on the page
* themes         — from ``/wp-content/themes/<slug>/`` references
* users          — author enumeration via the REST API and ``?author=N``
* xmlrpc         — whether xmlrpc.php is enabled (brute-force surface)
* readme / license exposure
* weak config files (wp-config.php backups)

This module never attempts logins or password attacks.
"""

from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin

from ..core import tools
from ..core.context import ModuleContext
from ..utils.helpers import dedupe, truncate

PLUGIN_RE = re.compile(r"/wp-content/plugins/([a-z0-9][a-z0-9._-]{1,60})/", re.IGNORECASE)
THEME_RE = re.compile(r"/wp-content/themes/([a-z0-9][a-z0-9._-]{1,60})/", re.IGNORECASE)
VERSION_PATTERNS = [
    re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([\d.]+)', re.IGNORECASE),
    re.compile(r'WordPress\s*([\d]+\.[\d.]+)', re.IGNORECASE),
    re.compile(r'ver=([\d.]+)(?:&|["\'])', re.IGNORECASE),
]
WP_MARKERS = ("wp-content", "wp-includes", "/wp-json", "wp-emoji", "wp-block-")
USER_AGENT_SLUGS = ("admin", "administrator", "webmaster", "editor", "author", "test")


class WordPressModule:
    name = "wordpress"
    label = "WordPress Enumeration"

    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.state = ctx.state
        self.detected_sites: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    def detect(self, url: str) -> Optional[Dict[str, Any]]:
        """Return a WordPress record if the site looks like WordPress."""
        resp = self.ctx.http.get(url, timeout=self.ctx.cfg.timeout)
        if not resp.ok:
            return None
        body = resp.body or ""
        lowered = body.lower()
        score = sum(1 for marker in WP_MARKERS if marker in lowered)

        version = ""
        for pattern in VERSION_PATTERNS:
            match = pattern.search(body)
            if match:
                version = match.group(1)
                break

        if score < 2 and not version:
            return None

        site = {
            "url": url,
            "version": version,
            "plugins": sorted(set(PLUGIN_RE.findall(body))),
            "themes": sorted(set(THEME_RE.findall(body))),
            "xmlrpc": None,
            "users": [],
            "readme": None,
            "wp_config_backups": [],
            "rest_api": None,
            "evidence": f"{score} WordPress marker(s) in HTML",
        }
        return site

    # ------------------------------------------------------------------
    def _check_rest_api(self, base: str) -> Dict[str, Any]:
        info: Dict[str, Any] = {"url": "", "status": 0, "users": []}
        url = f"{base.rstrip('/')}/wp-json/wp/v2/users"
        resp = self.ctx.http.get(url, timeout=self.ctx.cfg.timeout)
        info["url"] = url
        info["status"] = resp.status
        if resp.ok and resp.body.strip().startswith("["):
            try:
                users = json.loads(resp.body)
            except json.JSONDecodeError:
                users = []
            if isinstance(users, list):
                for entry in users:
                    if not isinstance(entry, dict):
                        continue
                    info["users"].append({
                        "id": entry.get("id"),
                        "name": entry.get("name", ""),
                        "slug": entry.get("slug", ""),
                        "description": truncate(entry.get("description", ""), 120),
                    })
        return info

    def _check_author_enum(self, base: str) -> List[Dict[str, Any]]:
        """``/?author=N`` redirects to ``/author/<slug>/`` when enabled."""
        found: List[Dict[str, Any]] = []
        for index in range(1, 6):
            url = f"{base.rstrip('/')}/?author={index}"
            resp = self.ctx.http.get(url, timeout=self.ctx.cfg.timeout, follow_redirects=False)
            if not resp.ok:
                continue
            location = resp.header("location")
            if resp.status in (301, 302) and "/author/" in location:
                slug = location.rstrip("/").split("/author/")[-1]
                found.append({"author_id": index, "slug": slug})
        return found

    def _check_files(self, base: str) -> Dict[str, Any]:
        """Check commonly exposed WordPress files (read-only GETs)."""
        checks = {
            "readme": "/readme.html",
            "xmlrpc": "/xmlrpc.php",
            "wp_config_backup": "/wp-config.php.bak",
            "wp_config_old": "/wp-config.php~",
            "install": "/wp-admin/install.php",
            "debug_log": "/wp-content/debug.log",
        }
        results: Dict[str, Any] = {}
        for label, path in checks.items():
            resp = self.ctx.http.get(f"{base.rstrip('/')}{path}", timeout=self.ctx.cfg.timeout)
            results[label] = {
                "path": path,
                "status": resp.status,
                "length": len(resp.body),
            }
        return results

    # ------------------------------------------------------------------
    def enumerate_site(self, site: Dict[str, Any]) -> None:
        base = site["url"]
        checks = self._check_files(base)
        site["files"] = checks

        readme = checks.get("readme", {})
        if readme.get("status") == 200:
            resp = self.ctx.http.get(urljoin(base, "/readme.html"), timeout=self.ctx.cfg.timeout)
            match = re.search(r"Version\s*([\d.]+)", resp.body or "", re.IGNORECASE)
            site["readme"] = match.group(1) if match else "accessible"

        xmlrpc = checks.get("xmlrpc", {})
        site["xmlrpc"] = xmlrpc.get("status") == 405 or xmlrpc.get("status") == 200

        for label in ("wp_config_backup", "wp_config_old", "debug_log"):
            entry = checks.get(label, {})
            if entry.get("status") == 200:
                site["wp_config_backups"].append(entry["path"])

        rest = self._check_rest_api(base)
        site["rest_api"] = rest
        site["users"] = dedupe(
            [rest and u.get("slug", "") for u in rest.get("users", []) if u.get("slug")]
            + [entry["slug"] for entry in self._check_author_enum(base)]
        )

        if not site.get("version") and site.get("readme") not in (None, "accessible"):
            site["version"] = str(site["readme"])

        # Optional: wpscan gives plugin versions and CVE data.
        if tools.tool_available("wpscan"):
            result = tools.wpscan(base, timeout=600)
            if result.ok and result.items:
                try:
                    payload = json.loads(result.items[0])
                except json.JSONDecodeError:
                    payload = None
                if isinstance(payload, dict):
                    site["wpscan"] = {
                        "version": (payload.get("version") or {}).get("number", ""),
                        "plugins": list((payload.get("plugins") or {}).keys())[:50],
                        "themes": list((payload.get("themes") or {}).keys())[:50],
                    }
                    for slug in site["wpscan"]["plugins"]:
                        if slug not in site["plugins"]:
                            site["plugins"].append(slug)
                    for slug in site["wpscan"]["themes"]:
                        if slug not in site["themes"]:
                            site["themes"].append(slug)

    # ------------------------------------------------------------------
    def run(self) -> Dict[str, object]:
        ctx = self.ctx
        urls = dedupe(ctx.state.live_urls())
        if not urls:
            ctx.emit("WordPress: no live endpoints to check")
            self._write([])
            return {"sites": 0}

        ctx.emit(f"Checking {len(urls)} endpoint(s) for WordPress")

        candidates: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=max(1, min(ctx.cfg.threads, 15))) as pool:
            futures = {pool.submit(self.detect, url): url for url in urls}
            for future in as_completed(futures):
                url = futures[future]
                try:
                    site = future.result()
                except Exception as exc:  # noqa: BLE001
                    ctx.record_error(self.name, f"{url}: {exc}")
                    continue
                if site:
                    candidates.append(site)
                    ctx.emit(f"  WordPress detected: {url}")

        if not candidates:
            ctx.emit("WordPress: not detected on any endpoint")
            self._write([])
            return {"sites": 0}

        for site in candidates:
            ctx.emit(f"Enumerating {site['url']}")
            try:
                self.enumerate_site(site)
            except Exception as exc:  # noqa: BLE001
                ctx.record_error(self.name, f"{site['url']}: {exc}")
        self.detected_sites = candidates
        self.state.wordpress_sites = candidates
        self.state.summary["wordpress"] = candidates
        self._write(candidates)

        total_plugins = sum(len(s["plugins"]) for s in candidates)
        total_users = sum(len(s.get("users") or []) for s in candidates)
        ctx.emit(
            f"WordPress: {len(candidates)} site(s), {total_plugins} plugin(s), "
            f"{total_users} enumerated user(s)"
        )
        return {
            "sites": len(candidates),
            "plugins": total_plugins,
            "users": total_users,
        }

    # ------------------------------------------------------------------
    def _write(self, sites: List[Dict[str, Any]]) -> None:
        out = self.ctx.out
        lines: List[str] = []
        for site in sites:
            add = lines.append
            add(f"# {site['url']}")
            add(f"  version : {site.get('version') or 'unknown'}")
            add(f"  evidence: {site.get('evidence', '')}")
            if site.get("xmlrpc") is not None:
                add(f"  xmlrpc  : {'enabled' if site['xmlrpc'] else 'not detected'}")
            if site.get("plugins"):
                add("  plugins :")
                for slug in site["plugins"]:
                    add(f"    {slug}")
            if site.get("themes"):
                add("  themes  :")
                for slug in site["themes"]:
                    add(f"    {slug}")
            if site.get("users"):
                add("  users   :")
                for user in site["users"]:
                    add(f"    {user}")
            if site.get("wp_config_backups"):
                add("  exposed files:")
                for path in site["wp_config_backups"]:
                    add(f"    {path}")
            add("")
        out.write("wordpress", "wordpress.txt", lines)

        out.write("wordpress", "plugins.txt", dedupe(
            slug for site in sites for slug in site.get("plugins", [])
        ))
        out.write("wordpress", "themes.txt", dedupe(
            slug for site in sites for slug in site.get("themes", [])
        ))
        out.write("wordpress", "users.txt", dedupe(
            f"{site['url']}\t{user}" for site in sites for user in (site.get("users") or [])
        ))
        out.write_json("wordpress", "wordpress.json", sites)