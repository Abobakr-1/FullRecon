"""G. JavaScript analysis: endpoints, secrets, comments and config references.

Secrets are reported as *patterns with redacted values* only.  FullRecon never
uses, validates, or submits discovered credentials.
"""

from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlsplit

from ..core.context import ModuleContext
from ..utils.helpers import dedupe, extract_urls, truncate, url_host
from ..utils.validators import is_ip

# (name, regex, confidence) - patterns are deliberately specific to limit noise.
SECRET_PATTERNS: List[Tuple[str, str, str]] = [
    ("AWS Access Key ID", r"\b(AKIA[0-9A-Z]{16})\b", "high"),
    ("AWS Secret Access Key", r"(?i)aws[_.-]?(?:secret|private)[_.-]?(?:access[_.-]?)?key\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]", "high"),
    ("Google API Key", r"\b(AIza[0-9A-Za-z\-_]{35})\b", "high"),
    ("Google OAuth Client ID", r"\b([0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com)\b", "medium"),
    ("Stripe Live Secret", r"\b(sk_live_[0-9a-zA-Z]{24,})\b", "high"),
    ("Stripe Test Secret", r"\b(sk_test_[0-9a-zA-Z]{24,})\b", "medium"),
    ("GitHub Token", r"\b(gh[pousr]_[A-Za-z0-9]{36,})\b", "high"),
    ("GitLab Token", r"\b(glpat-[A-Za-z0-9\-_]{20,})\b", "high"),
    ("Slack Token", r"\b(xox[abprs]-[0-9A-Za-z\-]{10,})\b", "high"),
    ("Slack Webhook", r"(https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,})", "high"),
    ("SendGrid Key", r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b", "high"),
    ("Mailgun Key", r"\b(key-[0-9a-f]{32})\b", "medium"),
    ("Twilio Account SID", r"\b(AC[0-9a-fA-F]{32})\b", "medium"),
    ("Firebase URL", r"(https://[a-z0-9-]+\.firebaseio\.com)", "low"),
    ("Firebase API Key", r"(?i)firebase[_.-]?api[_.-]?key\s*[:=]\s*['\"]([A-Za-z0-9_\-]{30,})['\"]", "medium"),
    ("Private Key Block", r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----)", "high"),
    ("JWT", r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b", "medium"),
    ("Basic Auth in URL", r"(https?://[^\s/'\":@]+:[^\s/'\":@]+@[^\s/'\"\s]+)", "high"),
    ("Generic API Key Assignment", r"(?i)(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret[_-]?key)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,64})['\"]", "low"),
    ("Algolia Key", r"(?i)algolia[_.-]?(?:api[_.-]?)?key\s*[:=]\s*['\"]([a-f0-9]{32})['\"]", "medium"),
    ("Mapbox Token", r"\b(pk\.[A-Za-z0-9_\-]{60,})\b", "medium"),
    ("Heroku API Key", r"(?i)heroku[_.-]?api[_.-]?key\s*[:=]\s*['\"]([0-9a-f-]{36})['\"]", "medium"),
    ("Cloudinary URL", r"(cloudinary://[0-9]+:[A-Za-z0-9_\-]+@[A-Za-z0-9_\-]+)", "medium"),
]

COMPILED_SECRETS = [(name, re.compile(pattern), confidence) for name, pattern, confidence in SECRET_PATTERNS]

ENDPOINT_PATTERNS = [
    re.compile(r"""(?:fetch|axios(?:\.(?:get|post|put|delete|patch))?|\.open)\s*\(\s*['"`]([^'"`\s]{2,300})['"`]"""),
    re.compile(r"""(?:url|uri|endpoint|path|action|baseURL|baseUrl)\s*[:=]\s*['"`](/[^'"`\s]{1,300})['"`]"""),
    re.compile(r"""['"`](/(?:api|v\d|rest|graphql|internal|admin|oauth|auth)[^'"`\s]{0,200})['"`]"""),
    re.compile(r"""['"`](https?://[^'"`\s]{6,300})['"`]"""),
]

COMMENT_RE = re.compile(r"//[^\n]{4,300}|/\*(?:[^*]|\*(?!/)){4,400}\*/", re.DOTALL)
CONFIG_REF_RE = re.compile(
    r"""(?i)(?:window\.|process\.env\.|__ENV__|config\.)([A-Za-z_][A-Za-z0-9_.]{2,60})"""
)
SENSITIVE_COMMENT_HINTS = (
    "todo", "fixme", "hack", "password", "passwd", "secret", "token", "api_key",
    "apikey", "credential", "internal", "staging", "admin", "debug", "backdoor",
    "remove", "temporary", "temp", "private", "leak", "vulnerab",
)


class JavaScriptModule:
    name = "javascript"
    label = "JavaScript Analysis"

    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.state = ctx.state
        self.secrets: List[Dict[str, str]] = []
        self.comments: List[Dict[str, str]] = []
        self.config_refs: Set[str] = set()
        self.endpoints: Set[str] = set()

    # ------------------------------------------------------------------
    def _collect_files(self) -> List[str]:
        cfg = self.ctx.cfg
        files: List[str] = []
        files.extend(self.state.js_files)

        # JS referenced by known URLs.
        for url in self.state.urls:
            path = urlsplit(url).path.lower()
            if path.endswith((".js", ".mjs", ".jsx", ".ts")):
                files.append(url)

        # Common bundles referenced on live pages (already crawled, but be safe).
        files = [f for f in dedupe(files) if self._worth_fetching(f)]
        return files[: cfg.js_max_files]

    def _worth_fetching(self, url: str) -> bool:
        host = url_host(url)
        if not host or not self.ctx.in_scope(host):
            return False
        lower = url.lower()
        if lower.endswith((".min.js", ".js", ".mjs", ".jsx", ".ts")):
            return True
        return ".js?" in lower

    # ------------------------------------------------------------------
    def analyse(self, url: str) -> Optional[Dict[str, object]]:
        resp = self.ctx.http.get(url, timeout=self.ctx.cfg.timeout, max_bytes=self.ctx.cfg.js_max_size)
        if not resp.ok or not resp.body:
            return None
        body = resp.body
        kind = resp.header("content-type").split(";")[0] or "application/javascript"
        endpoints = self._extract_endpoints(body, url)
        secrets = self._find_secrets(body, url)
        comments = self._find_comments(body, url)
        refs = self._find_config_refs(body)
        return {
            "url": url,
            "size": len(body),
            "mime": kind,
            "endpoints": endpoints,
            "secrets": secrets,
            "comments": comments,
            "config_refs": refs,
        }

    # ------------------------------------------------------------------
    def _extract_endpoints(self, body: str, base_url: str) -> List[str]:
        found: List[str] = []
        for pattern in ENDPOINT_PATTERNS:
            for match in pattern.finditer(body):
                candidate = match.group(1).strip()
                if not candidate or candidate.startswith("//"):
                    continue
                if candidate.startswith("/"):
                    parts = urlsplit(base_url)
                    candidate = f"{parts.scheme}://{parts.netloc}{candidate}"
                elif not candidate.startswith(("http://", "https://")):
                    continue
                host = url_host(candidate)
                if host and (self.ctx.in_scope(host) or self.ctx.scope.allows_host(host).allowed):
                    found.append(candidate)
        return dedupe(found)[:500]

    def _find_secrets(self, body: str, url: str) -> List[Dict[str, str]]:
        hits: List[Dict[str, str]] = []
        for name, regex, confidence in COMPILED_SECRETS:
            for match in regex.finditer(body):
                value = match.group(1) if match.groups() else match.group(0)
                if not value or len(value) < 8:
                    continue
                if _looks_like_placeholder(value):
                    continue
                hits.append({
                    "type": name,
                    "confidence": confidence,
                    "value_redacted": _redact(value),
                    "length": str(len(value)),
                    "source": url,
                })
                if len(hits) >= 200:
                    return hits
        return hits

    def _find_comments(self, body: str, url: str) -> List[Dict[str, str]]:
        out = []
        for match in COMMENT_RE.finditer(body):
            text = match.group(0).strip()
            if len(text) > 400:
                continue
            lowered = text.lower()
            if not any(hint in lowered for hint in SENSITIVE_COMMENT_HINTS):
                continue
            out.append({"source": url, "comment": truncate(text, 300)})
            if len(out) >= 100:
                break
        return out

    @staticmethod
    def _find_config_refs(body: str) -> List[str]:
        refs = {m.group(1) for m in CONFIG_REF_RE.finditer(body)}
        return sorted(ref for ref in refs if len(ref) > 3)[:200]

    # ------------------------------------------------------------------
    def run(self) -> Dict[str, object]:
        cfg = self.ctx.cfg
        files = self._collect_files()
        if not files:
            self.ctx.warn("no JavaScript files discovered")
            self._write(files, [])
            return {"js_files": 0}

        self.ctx.emit(f"Analysing {len(files)} JavaScript file(s)")
        analysed: List[Dict[str, object]] = []
        workers = max(1, min(cfg.threads, 20))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(self.analyse, url): url for url in files}
            for future in as_completed(futures):
                url = futures[future]
                try:
                    result = future.result()
                except Exception as exc:  # noqa: BLE001
                    self.ctx.record_error(self.name, f"{url}: {exc}")
                    continue
                if not result:
                    continue
                analysed.append(result)
                self.endpoints.update(result["endpoints"])
                self.secrets.extend(result["secrets"])
                self.comments.extend(result["comments"])
                self.config_refs.update(result["config_refs"])

        self.state.js_files = files
        self.state.js_endpoints = sorted(self.endpoints)
        self.state.js_secrets = self.secrets
        self.state.js_comments = self.comments
        self.state.js_config_refs = sorted(self.config_refs)
        self._write(files, analysed)

        high = sum(1 for s in self.secrets if s["confidence"] == "high")
        self.ctx.emit(
            f"JavaScript: {len(files)} file(s), {len(self.endpoints)} endpoint(s), "
            f"{len(self.secrets)} secret pattern(s) ({high} high confidence)"
        )
        if self.secrets:
            self.ctx.warn(
                "Potential secrets found - values are redacted and were NOT used. "
                "Report them responsibly."
            )
        return {
            "js_files": len(files),
            "endpoints": len(self.endpoints),
            "secrets": len(self.secrets),
            "high_confidence": high,
        }

    # ------------------------------------------------------------------
    def _write(self, files: List[str], analysed: List[Dict[str, object]]) -> None:
        out = self.ctx.out
        out.write("javascript", "javascript_files.txt", sorted(files))
        out.write("javascript", "extracted_endpoints.txt", sorted(self.endpoints))

        secret_lines = [
            "{confidence:<7} {type:<26} {value}  ({source})".format(
                confidence=s["confidence"], type=s["type"],
                value=s["value_redacted"], source=s["source"],
            )
            for s in self.secrets
        ]
        out.write("javascript", "potential_exposures.txt", secret_lines)
        out.write("javascript", "sensitive_comments.txt", [
            f"{c['source']}\t{c['comment']}" for c in self.comments
        ])
        out.write("javascript", "config_references.txt", sorted(self.config_refs))
        out.write("javascript", "all_js_urls_inline.txt", [
            f"{a['url']}\t{a['size']}\t{a['mime']}" for a in analysed
        ])
        out.write_json("javascript", "javascript_analysis.json", {
            "files": analysed,
            "secrets": self.secrets,
            "comments": self.comments,
            "config_references": sorted(self.config_refs),
            "endpoints": sorted(self.endpoints),
            "note": "Secret values are redacted. Do not use discovered credentials.",
        })


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_PLACEHOLDER_HINTS = (
    "your_", "your-", "xxxx", "example", "replace", "changeme", "dummy",
    "placeholder", "0000000000", "abcdefgh", "test_key", "sample",
)


def _looks_like_placeholder(value: str) -> bool:
    lowered = value.lower()
    if any(hint in lowered for hint in _PLACEHOLDER_HINTS):
        return True
    if len(set(value)) <= 3:
        return True
    return False


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    keep = max(4, min(6, len(value) // 4))
    return f"{value[:keep]}...{value[-keep:]} [len={len(value)}]"