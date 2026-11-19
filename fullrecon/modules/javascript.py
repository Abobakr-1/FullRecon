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

# Mapped from the recon roadmap's manual `grep` list, items 8-13.
API_VERSION_RE = re.compile(r"""['"`](/api/v[0-9]+[^'"`\s]{0,200})['"`]""", re.IGNORECASE)
WEBSOCKET_RE = re.compile(r"""(wss?://[^\s'"`<>]{4,300})""", re.IGNORECASE)
SOURCE_MAP_RE = re.compile(r"""[^\s'"`<>]{2,300}?\.map(?:\?[^\s'"`<>]*)?(?=['"`\s])""")
SENSITIVE_FILE_RE = re.compile(
    r"""[/A-Za-z0-9_.-]{1,200}?\.(?:php|json|xml|config|graphql|ya?ml|env|sql|bak|old)\b""",
    re.IGNORECASE,
)
CLIENT_CALL_RE = re.compile(
    r"""(fetch\s*\(|axios(?:\.\w+)?\s*\(|new\s+XMLHttpRequest|\.ajax\s*\(|EventSource\s*\()"""
)
# Parameter names the roadmap greps for (item 7).
PARAM_NAME_RE = re.compile(
    r"""(?i)\b(id|userId|user_id|accountId|account_id|redirect|returnUrl|return_url|"""
    r"""role|tenant|org|organization|admin|isAdmin|debug|token|apiKey|api_key)\b"""
)
JS_SENSITIVE_HINTS = (
    "admin", "administrator", "management", "login", "logout", "signin", "signup",
    "register", "auth", "user", "account", "profile", "settings",
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
        self.api_versions: Set[str] = set()
        self.websockets: Set[str] = set()
        self.source_maps: Set[str] = set()
        self.sensitive_files: Set[str] = set()
        self.params: Set[str] = set()
        self.client_calls: Dict[str, int] = {}

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
            "api_versions": self._find_api_versions(body),
            "websockets": self._find_websockets(body),
            "source_maps": self._find_source_maps(body),
            "sensitive_files": self._find_sensitive_files(body),
            "client_calls": self._count_client_calls(body),
            "params": self._find_params(body),
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

    # -- roadmap grep equivalents (items 8-13) -------------------------
    @staticmethod
    def _find_api_versions(body: str) -> List[str]:
        """Item 8: ``grep -Eo '/api/v[0-9]+[^\"'\\'' ]*'``"""
        return sorted({m.group(1) for m in API_VERSION_RE.finditer(body)})[:100]

    @staticmethod
    def _find_websockets(body: str) -> List[str]:
        """Item 9: ``grep -Ei 'ws://|wss://|websocket'``"""
        return sorted({m.group(1).rstrip(".,;") for m in WEBSOCKET_RE.finditer(body)})[:50]

    @staticmethod
    def _find_source_maps(body: str) -> List[str]:
        """Item 12: ``grep -Eo '[^\"'\\'' ]+\\.map'``"""
        found = {m.group(0) for m in SOURCE_MAP_RE.finditer(body)}
        # Reject obvious noise such as CSS map fragments inside strings.
        return sorted(f for f in found if len(f) < 300)[:50]

    @staticmethod
    def _find_sensitive_files(body: str) -> List[str]:
        """Item 10: interesting file paths ending in php/json/xml/config/graphql."""
        found = {m.group(0) for m in SENSITIVE_FILE_RE.finditer(body)}
        return sorted(f for f in found if len(f) > 3 and "/" in f)[:100]

    @staticmethod
    def _count_client_calls(body: str) -> Dict[str, int]:
        """Item 13: how the application communicates (fetch/axios/XHR/SSE)."""
        counts: Dict[str, int] = {}
        for match in CLIENT_CALL_RE.finditer(body):
            label = match.group(1).split("(")[0].strip().lower()
            if label.startswith("new xmlhttprequest"):
                label = "xmlhttprequest"
            counts[label] = counts.get(label, 0) + 1
        return counts

    @staticmethod
    def _find_params(body: str) -> List[str]:
        """Item 7: parameter names worth reviewing (id, redirectUrl, role, ...)."""
        return sorted({m.group(1) for m in PARAM_NAME_RE.finditer(body)})[:100]

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
                self.api_versions.update(result.get("api_versions", []))
                self.websockets.update(result.get("websockets", []))
                self.source_maps.update(result.get("source_maps", []))
                self.sensitive_files.update(result.get("sensitive_files", []))
                self.params.update(result.get("params", []))
                for label, count in (result.get("client_calls") or {}).items():
                    self.client_calls[label] = self.client_calls.get(label, 0) + count

        self.state.js_files = files
        self.state.js_endpoints = sorted(self.endpoints)
        self.state.js_secrets = self.secrets
        self.state.js_comments = self.comments
        self.state.js_config_refs = sorted(self.config_refs)
        self.state.js_api_versions = sorted(self.api_versions)
        self.state.js_websockets = sorted(self.websockets)
        self.state.js_source_maps = sorted(self.source_maps)
        self.state.js_sensitive_files = sorted(self.sensitive_files)
        self.state.js_client_calls = dict(self.client_calls)
        self.state.js_params = sorted(self.params)
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
        out.write("javascript", "api_versions.txt", sorted(self.api_versions))
        out.write("javascript", "websocket_endpoints.txt", sorted(self.websockets))
        out.write("javascript", "source_maps.txt", sorted(self.source_maps))
        out.write("javascript", "interesting_file_paths.txt", sorted(self.sensitive_files))
        out.write("javascript", "parameter_names.txt", sorted(self.params))
        out.write("javascript", "client_calls.txt", [
            f"{label}\t{count}" for label, count in sorted(self.client_calls.items())
        ])
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
