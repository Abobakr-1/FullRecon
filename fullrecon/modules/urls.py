"""E. URL and endpoint discovery: crawling, archives, JS references, params."""

from __future__ import annotations

import json
import re
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import quote, urlsplit

from ..core import tools
from ..core.context import ModuleContext
from ..config import INTERESTING_KEYWORDS
from ..utils.helpers import (
    absolute_url,
    dedupe,
    extract_html_info,
    extract_urls,
    is_interesting,
    query_params,
    url_host,
)
from ..utils.validators import in_domain, same_site


class UrlModule:
    name = "urls"
    label = "URL & Endpoint Discovery"

    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.state = ctx.state
        self.seen: Set[str] = set()
        self.results: List[str] = []
        self.sources: Dict[str, int] = {}

    # ------------------------------------------------------------------
    def _add(self, urls: Iterable[str], source: str) -> int:
        added = 0
        for url in urls:
            if not url:
                continue
            normalised = url.strip()
            if len(normalised) > 2048:
                continue
            host = url_host(normalised)
            if not host or not self.ctx.in_scope(host):
                continue
            if normalised in self.seen:
                continue
            self.seen.add(normalised)
            self.results.append(normalised)
            added += 1
        if added:
            self.sources[source] = self.sources.get(source, 0) + added
        return added

    # ------------------------------------------------------------------
    def crawl(self, seeds: List[str]) -> None:
        cfg = self.ctx.cfg
        queue = deque((url, 0) for url in seeds)
        visited: Set[str] = set()
        pages = 0
        js_files: Set[str] = set()

        while queue and pages < cfg.crawl_max_pages and len(self.results) < cfg.crawl_max_urls:
            url, depth = queue.popleft()
            if url in visited:
                continue
            visited.add(url)
            resp = self.ctx.http.get(url, timeout=cfg.url_timeout)
            if not resp.ok:
                continue
            pages += 1
            content_type = resp.header("content-type", "").lower()
            if "javascript" in content_type:
                js_files.add(url)
                continue
            if "html" not in content_type and content_type and pages > 1:
                continue

            info = extract_html_info(resp.body, resp.url)
            links = info["hrefs"] + info["forms"] + info["links"]
            self._add(links, "crawl")
            js_files.update(info["scripts"])
            self._add(info["scripts"], "crawl-js")
            # Inline endpoints in markup (rare, but cheap to catch).
            self._add(extract_urls(resp.body), "crawl-inline")

            if depth < cfg.crawl_depth:
                for link in links:
                    if link in visited:
                        continue
                    if not self._crawlable(link):
                        continue
                    queue.append((link, depth + 1))

        if js_files:
            self.state.js_files = dedupe(list(self.state.js_files) + list(js_files))
        self.ctx.emit(f"  crawled {pages} page(s), {len(js_files)} JS reference(s)")

    def _crawlable(self, url: str) -> bool:
        parts = urlsplit(url)
        path = parts.path.lower()
        if re.search(r"\.(png|jpe?g|gif|svg|ico|webp|css|woff2?|ttf|eot|mp4|mp3|pdf|zip|gz|rar|7z)$", path):
            return False
        return True

    # ------------------------------------------------------------------
    def wayback(self) -> None:
        cfg = self.ctx.cfg
        domain = cfg.domain
        url = (
            f"https://web.archive.org/cdx/search/cdx?url=*.{quote(domain)}/*"
            "&output=json&collapse=urlkey&fl=original&limit=20000&filter=statuscode:200"
        )
        resp = self.ctx.http.get(url, timeout=30, external=True)
        if not resp.ok or not resp.body.strip():
            self.ctx.debug("wayback returned no data: %s", resp.error or resp.status)
            return
        try:
            rows = json.loads(resp.body)
        except json.JSONDecodeError:
            return
        if not isinstance(rows, list) or len(rows) < 2:
            return
        urls = [row[0] for row in rows[1:] if row]
        added = self._add(urls, "wayback")
        self.ctx.emit(f"  wayback: {added} URL(s)")

    def commoncrawl(self) -> None:
        domain = self.ctx.cfg.domain
        from ..modules.subdomains import Sources

        index = Sources(self.ctx)._latest_commoncrawl_index()
        if not index:
            return
        url = (
            f"http://index.commoncrawl.org/{index}-index?url=*.{quote(domain)}/*"
            "&output=json&limit=10000&fl=url"
        )
        resp = self.ctx.http.get(url, timeout=30, external=True)
        if not resp.ok:
            return
        urls = []
        for line in resp.body.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                urls.append(json.loads(line).get("url", ""))
            except json.JSONDecodeError:
                continue
        added = self._add(urls, "commoncrawl")
        self.ctx.emit(f"  commoncrawl: {added} URL(s)")

    def katana_crawl(self, seeds: List[str]) -> None:
        """Crawl with katana when installed (parses JavaScript, unlike the built-in crawler)."""
        cfg = self.ctx.cfg
        if not (cfg.use_external_tools and cfg.katana_enabled and tools.tool_available("katana")):
            return
        for seed in seeds[:5]:
            result = tools.katana(
                seed,
                depth=cfg.katana_depth,
                js_crawl=True,
                timeout=min(cfg.external_tool_timeout, 300.0),
            )
            if result.ok:
                added = self._add(result.items, "katana")
                self.ctx.emit(f"  katana: {added} URL(s) from {seed}")
            else:
                self.ctx.debug("katana failed for %s: %s", seed, result.error)

    def historical_tools(self) -> None:
        """gau / waybackurls when installed, complementing the CDX API."""
        cfg = self.ctx.cfg
        if not (cfg.use_external_tools and cfg.gau_enabled):
            return
        domain = cfg.domain
        if tools.tool_available("gau"):
            result = tools.gau(domain, timeout=min(cfg.external_tool_timeout, 180))
            if result.ok:
                added = self._add(result.items, "gau")
                self.ctx.emit(f"  gau: {added} URL(s)")
            else:
                self.ctx.debug("gau failed: %s", result.error)
        if tools.tool_available("waybackurls"):
            result = tools.waybackurls(domain, timeout=min(cfg.external_tool_timeout, 180))
            if result.ok:
                added = self._add(result.items, "waybackurls")
                self.ctx.emit(f"  waybackurls: {added} URL(s)")

    def robots_and_sitemaps(self, seeds: List[str]) -> None:
        """robots.txt, sitemap.xml and security.txt are cheap high-yield files."""
        for seed in seeds[:20]:
            root = "{0.scheme}://{0.netloc}".format(urlsplit(seed))
            for path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
                resp = self.ctx.http.get(root + path, timeout=self.ctx.cfg.url_timeout)
                if not resp.ok or resp.status >= 400:
                    continue
                self._add(extract_urls(resp.body), f"wellknown{path}")
                if path == "/robots.txt":
                    paths = []
                    for line in resp.body.splitlines():
                        if line.lower().startswith(("disallow:", "allow:")):
                            value = line.split(":", 1)[1].strip()
                            if value and value != "/":
                                paths.append(root + value if value.startswith("/") else value)
                    self._add(paths, "robots")

    # ------------------------------------------------------------------
    def run(self) -> Dict[str, object]:
        cfg = self.ctx.cfg
        seeds = dedupe(self.state.live_urls())[:50]
        if not seeds:
            seeds = [f"https://{cfg.domain}/", f"http://{cfg.domain}/"]
            seeds = [s for s in seeds if self.ctx.in_scope(url_host(s))]
        if not seeds:
            self.ctx.warn("no in-scope seed URLs for crawling")
            return {"urls": 0}

        self.ctx.emit(f"Crawling {len(seeds)} seed(s), depth {cfg.crawl_depth}")

        # Everything below writes into self.results; sources are attributed.
        self._add(seeds, "seed")
        self.robots_and_sitemaps(seeds)
        self.crawl(seeds)
        self.katana_crawl(seeds)

        if not cfg.passive_only:
            self.historical_tools()
        if not cfg.passive_only and cfg.wayback_urls:
            self.wayback()
        if not cfg.passive_only and cfg.commoncrawl_urls:
            self.commoncrawl()

        self.results = dedupe(self.results)
        interesting = [u for u in self.results if self._is_interesting_url(u)]

        self.state.urls = self.results
        self.state.interesting_urls = interesting
        self.state.url_sources = dict(self.sources)
        self._write(seeds)
        self.ctx.emit(
            f"URLs: {len(self.results)} unique, {len(interesting)} interesting, "
            f"{len({url_host(u) for u in self.results})} host(s)"
        )
        return {"urls": len(self.results), "interesting": len(interesting)}

    # ------------------------------------------------------------------
    @staticmethod
    def _is_interesting_url(url: str) -> bool:
        lowered = url.lower()
        if any(ext in lowered for ext in (".env", ".git/", ".bak", ".sql", ".zip", ".log", "config.", ".json", ".xml")):
            return True
        if len(query_params(url)) > 0:
            return True
        return is_interesting(url, INTERESTING_KEYWORDS)

    def _write(self, seeds: List[str]) -> None:
        out = self.ctx.out
        out.write("urls", "all_urls.txt", self.results)
        out.write("urls", "unique_urls.txt", dedupe(sorted(self.results)))
        out.write("urls", "interesting_urls.txt", sorted(self.state.interesting_urls))

        param_lines = []
        for url in self.results:
            params = query_params(url)
            if params:
                param_lines.append(f"{url}\t{','.join(dedupe(params))}")
        out.write("urls", "urls_with_parameters.txt", param_lines)
        out.write("urls", "urls_without_query.txt", dedupe([u.split("?")[0] for u in self.results]))
        out.write("urls", "js_files_from_crawl.txt", self.state.js_files)
        out.write_json("urls", "sources.json", self.sources)
        out.write_json("urls", "summary.json", {
            "total": len(self.results),
            "interesting": len(self.state.interesting_urls),
            "by_source": self.sources,
            "hosts": sorted({url_host(u) for u in self.results}),
        })