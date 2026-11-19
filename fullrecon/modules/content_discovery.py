"""H. Directory & content discovery with rate limiting and soft-404 detection."""

from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from ..core.context import ModuleContext
from ..config import SENSITIVE_EXTENSIONS
from ..utils.helpers import dedupe, load_wordlist, truncate
from ..utils.validators import in_domain

DEFAULT_WORDLIST = Path(__file__).resolve().parent.parent / "data" / "content_wordlist.txt"

# Extra checks that are useful even if a user wordlist omits them.
HIGH_VALUE_PATHS = [
    ".git/HEAD", ".env", ".env.local", ".aws/credentials", ".svn/entries",
    "backup.zip", "backup.tar.gz", "db.sql", "dump.sql", "www.zip",
    "server-status", "phpinfo.php", "info.php", "config.php.bak",
    "wp-config.php.bak", "web.config", "Dockerfile", "docker-compose.yml",
    ".well-known/security.txt", "robots.txt", "sitemap.xml", "crossdomain.xml",
    "actuator/health", "actuator/env", "api/swagger.json", "swagger.json",
]


class ContentModule:
    name = "content"
    label = "Directory & Content Discovery"

    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.state = ctx.state
        self.found: List[Dict[str, object]] = []
        self.baseline: Dict[str, str] = {}

    # ------------------------------------------------------------------
    def _wordlist(self) -> List[str]:
        cfg = self.ctx.cfg
        path = cfg.content_wordlist or str(DEFAULT_WORDLIST)
        words = [w for w in load_wordlist(path) if w and not w.startswith("#")] if Path(path).is_file() else []
        if not Path(path).is_file():
            self.ctx.warn(f"content wordlist not found: {path}")
        words.extend(HIGH_VALUE_PATHS)
        extensions = [e for e in cfg.content_extensions]
        expanded: List[str] = []
        for word in dedupe(words):
            word = word.strip("/")
            expanded.append(word)
            if extensions and "." not in word.rsplit("/", 1)[-1]:
                for ext in extensions:
                    if ext:
                        expanded.append(f"{word}.{ext}")
        return dedupe(expanded)[: cfg.content_max_paths]

    # ------------------------------------------------------------------
    def _baseline_for(self, base: str) -> str:
        """Fingerprint a random 404 so soft-404 pages are ignored."""
        if base in self.baseline:
            return self.baseline[base]
        token = hashlib.md5(base.encode()).hexdigest()[:16]
        resp = self.ctx.http.get(f"{base}/{token}-fullrecon-probe", timeout=self.ctx.cfg.timeout)
        signature = ""
        if resp.ok:
            signature = _signature(resp.status, resp.headers, resp.body)
        self.baseline[base] = signature
        return signature

    def _probe(self, base: str, path: str, baseline: str) -> Optional[Dict[str, object]]:
        url = f"{base}/{path.lstrip('/')}"
        resp = self.ctx.http.get(url, timeout=self.ctx.cfg.timeout)
        if not resp.ok:
            return None
        if resp.status in self.ctx.cfg.content_ignore_status:
            return None
        signature = _signature(resp.status, resp.headers, resp.body)
        if baseline and signature == baseline:
            return None  # soft 404
        if resp.status in (401, 403, 500, 502, 503):
            # These are still informative: access control and errors leak paths.
            pass
        return {
            "url": url,
            "path": path,
            "status": resp.status,
            "length": len(resp.body),
            "content_type": resp.header("content-type").split(";")[0],
            "redirect": resp.header("location"),
            "title": truncate(resp.title, 80),
        }

    # ------------------------------------------------------------------
    def run(self) -> Dict[str, object]:
        cfg = self.ctx.cfg
        if not cfg.content_discovery or cfg.passive_only:
            self.ctx.emit("content discovery skipped")
            return {"paths": 0}

        bases = self._bases()
        if not bases:
            return {"paths": 0}
        words = self._wordlist()
        if not words:
            self.ctx.warn("no wordlist entries to test")
            return {"paths": 0}


        for base in bases:
            baseline = self._baseline_for(base)
            if baseline:
                self.ctx.debug("soft-404 baseline for %s: %s", base, baseline[:60])

        per_base = max(1, cfg.content_max_paths // max(len(bases), 1))
        if len(words) > per_base:
            self.ctx.debug(
                "limiting content wordlist to %d entries per base URL", per_base
            )
            words = words[:per_base]
        total = len(words) * len(bases)
        self.ctx.emit(
            f"Probing {total} path(s) across {len(bases)} base URL(s) "
            f"at {cfg.rate_limit:g} req/s per host (~{total / max(cfg.rate_limit, 1):.0f}s)"
        )
        tasks = [(base, word) for base in bases for word in words]
        workers = max(1, min(cfg.threads, 25))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(self._probe, base, word, self.baseline.get(base, "")): (base, word)
                for base, word in tasks
            }
            for future in as_completed(futures):
                try:
                    result = future.result()
                except Exception as exc:  # noqa: BLE001
                    self.ctx.record_error(self.name, str(exc))
                    continue
                if result:
                    self.found.append(result)

        self.found.sort(key=lambda r: (r["url"]))
        interesting = [r for r in self.found if self._is_interesting(r)]
        self.state.content = self.found
        self.state.interesting_files = interesting
        self._write(interesting)

        self.ctx.emit(
            f"Content discovery: {len(self.found)} path(s) found, "
            f"{len(interesting)} interesting"
        )
        return {"paths": len(self.found), "interesting": len(interesting)}

    # ------------------------------------------------------------------
    def _bases(self) -> List[str]:
        bases: List[str] = []
        for url in self.state.live_urls():
            from urllib.parse import urlsplit

            parts = urlsplit(url)
            if not parts.scheme or not parts.netloc:
                continue
            base = f"{parts.scheme}://{parts.netloc}"
            if base not in bases and self.ctx.in_scope(parts.hostname or ""):
                bases.append(base)
        return bases[:10]

    @staticmethod
    def _is_interesting(record: Dict[str, object]) -> bool:
        url = str(record.get("url", "")).lower()
        status = int(record.get("status", 0) or 0)
        if status in (401, 403):
            return True
        if any(url.endswith(ext) or ext in url for ext in SENSITIVE_EXTENSIONS):
            return True
        if any(token in url for token in (
            "/admin", "/.git/", "/.env", "/backup", "/config", "/db", "/sql",
            "/dump", "/actuator", "/server-status", "/phpinfo", "/api", "/swagger",
            "/graphql", "/internal", "/private", "/secret", "/token",
        )):
            return True
        return False

    def _write(self, interesting: List[Dict[str, object]]) -> None:
        out = self.ctx.out
        discovered = [
            "{url:<70} {status:<4} {length:<8} {ctype}".format(
                url=r["url"], status=r["status"], length=r["length"],
                ctype=r.get("content_type") or "-",
            ).rstrip()
            for r in self.found
        ]
        out.write("content", "discovered_paths.txt", discovered)
        out.write("content", "interesting_files.txt", [
            "{url:<70} {status:<4} {length:<8} {title}".format(
                url=r["url"], status=r["status"], length=r["length"],
                title=r.get("title") or "",
            ).rstrip()
            for r in interesting
        ])
        out.write("content", "forbidden_paths.txt", [
            f"{r['url']} ({r['status']})" for r in self.found if r["status"] in (401, 403)
        ])
        out.write_json("content", "content_discovery.json", {
            "found": self.found,
            "interesting": interesting,
            "wordlist": str(self.ctx.cfg.content_wordlist or DEFAULT_WORDLIST),
            "soft_404_baselines": {k: v[:40] for k, v in self.baseline.items()},
        })


def _signature(status: int, headers: Dict[str, str], body: str) -> str:
    digest = hashlib.sha1()
    digest.update(str(status).encode())
    digest.update(body[:2048].encode("utf-8", "replace"))
    digest.update(headers.get("content-type", "").encode())
    return digest.hexdigest()