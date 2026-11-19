"""Shared helper functions: text files, URL handling, HTML parsing, subprocesses."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple
from urllib.parse import unquote, urlencode, urljoin, urlsplit, urlunsplit, parse_qsl

from .colors import Colors

# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------


def read_lines(path: str | Path) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return [line.strip() for line in fh if line.strip()]
    except (FileNotFoundError, IsADirectoryError, PermissionError):
        return []


def write_lines(path: str | Path, lines: Iterable[str]) -> int:
    """Write lines, preserving order, ensuring a trailing newline. Returns count."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with open(p, "w", encoding="utf-8", newline="\n") as fh:
        for line in lines:
            text = str(line).replace("\r", "").replace("\n", " ")
            if text.strip():
                fh.write(text.strip() + "\n")
                count += 1
    return count


def append_line(path: str | Path, line: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(str(line).replace("\n", " ").strip() + "\n")


def write_text(path: str | Path, text: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def read_text(path: str | Path, default: str = "") -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except (FileNotFoundError, IsADirectoryError, PermissionError):
        return default


def ensure_dir(path: str | Path) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


# ---------------------------------------------------------------------------
# Collections
# ---------------------------------------------------------------------------


def dedupe(items: Iterable[str], lowercase: bool = False) -> List[str]:
    """Order-preserving de-duplication."""
    seen: Set[str] = set()
    out: List[str] = []
    for item in items:
        if item is None:
            continue
        key = item.strip()
        if not key:
            continue
        if lowercase:
            key = key.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def dedupe_sorted(items: Iterable[str]) -> List[str]:
    return sorted({i.strip() for i in items if i and i.strip()})


def chunked(seq: Sequence, size: int) -> Iterator[Sequence]:
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------


def absolute_url(base: str, link: str) -> Optional[str]:
    link = (link or "").strip().strip("'\"")
    if not link or link.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
        return None
    if link.startswith("//"):
        scheme = urlsplit(base).scheme or "http"
        return f"{scheme}:{link}"
    try:
        joined = urljoin(base, link)
    except ValueError:
        return None
    parts = urlsplit(joined)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    return normalise_url(joined)


def normalise_url(url: str) -> str:
    """Lowercase host, drop fragments, keep query, sort query params."""
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return url.strip()
    host = (parts.hostname or "").lower()
    if not host:
        return url.strip()
    port = parts.port
    netloc = host
    if port and not ((parts.scheme == "http" and port == 80) or (parts.scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    query = parts.query
    if query:
        try:
            pairs = parse_qsl(query, keep_blank_values=True)
            pairs.sort()
            query = urlencode(pairs)
        except Exception:
            query = parts.query
    path = parts.path or "/"
    return urlunsplit((parts.scheme, netloc, path, query, ""))


def url_without_query(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


_URL_RE = re.compile(r"""https?://[^\s'"<>()\[\]{}\\^`|]+""", re.IGNORECASE)


def extract_urls(text: str) -> List[str]:
    found = []
    for match in _URL_RE.finditer(text or ""):
        candidate = match.group(0).rstrip(".,;:!?)]}\"'")
        if len(candidate) > 8 and "." in candidate:
            found.append(candidate)
    return dedupe(found)


_QUERY_PARAM_RE = re.compile(r"[?&]([A-Za-z0-9_\-\[\]\.]{1,40})=")


def query_params(url: str) -> List[str]:
    try:
        return [k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]
    except Exception:
        return [m.group(1) for m in _QUERY_PARAM_RE.finditer(url)]


def is_interesting(text: str, keywords: Optional[Sequence[str]] = None) -> bool:
    from ..config import INTERESTING_KEYWORDS
    value = (text or "").lower()
    for word in (keywords or INTERESTING_KEYWORDS):
        if word in value:
            return True
    return False


def safe_filename(value: str, max_len: int = 80) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value or "item")
    return cleaned.strip("._-")[:max_len] or "item"


# ---------------------------------------------------------------------------
# HTML parsing (regex based, no bs4 dependency)
# ---------------------------------------------------------------------------

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_META_GENERATOR_RE = re.compile(
    r"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']""", re.IGNORECASE
)
_META_GENERATOR_RE2 = re.compile(
    r"""<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator["']""", re.IGNORECASE
)
_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.IGNORECASE)
_LINK_HREF_RE = re.compile(r"""<link[^>]+href=["']([^"']+)["']""", re.IGNORECASE)
_ANCHOR_HREF_RE = re.compile(r"""<a[^>]+href=["']([^"']+)["']""", re.IGNORECASE)
_FORM_ACTION_RE = re.compile(r"""<form[^>]+action=["']([^"']*)["']""", re.IGNORECASE)
_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_BASE_HREF_RE = re.compile(r"""<base[^>]+href=["']([^"']+)["']""", re.IGNORECASE)


def _collapse(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def extract_title(html: str) -> str:
    if not html:
        return ""
    match = _TITLE_RE.search(html)
    if not match:
        return ""
    return _collapse(re.sub(r"<[^>]+>", "", match.group(1)))[:200]


def extract_html_info(html: str, base_url: str) -> Dict[str, list]:
    """Return scripts, links, forms and comments discovered in *html*."""
    html = html or ""
    info: Dict[str, list] = {
        "scripts": [],
        "links": [],
        "hrefs": [],
        "forms": [],
        "comments": [],
        "generators": [],
    }
    base_prefix = ""
    base_match = _BASE_HREF_RE.search(html)
    if base_match:
        resolved = absolute_url(base_url, base_match.group(1))
        if resolved:
            base_prefix = resolved
    root = base_prefix or base_url

    for match in _SCRIPT_SRC_RE.finditer(html):
        script = absolute_url(root, match.group(1))
        if script:
            info["scripts"].append(script)
    for match in _LINK_HREF_RE.finditer(html):
        link = absolute_url(root, match.group(1))
        if link:
            info["links"].append(link)
    for match in _ANCHOR_HREF_RE.finditer(html):
        href = absolute_url(root, match.group(1))
        if href:
            info["hrefs"].append(href)
    for match in _FORM_ACTION_RE.finditer(html):
        action = absolute_url(root, match.group(1) or root)
        if action:
            info["forms"].append(action)
    for match in _COMMENT_RE.finditer(html):
        comment = _collapse(match.group(1))
        if 3 < len(comment) < 400:
            info["comments"].append(comment)
    for regex in (_META_GENERATOR_RE, _META_GENERATOR_RE2):
        for match in regex.finditer(html):
            info["generators"].append(_collapse(match.group(1))[:120])
    return {k: dedupe(v) for k, v in info.items()}


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def run_command(
    args: Sequence[str],
    timeout: float = 300.0,
    input_text: Optional[str] = None,
    cwd: Optional[str] = None,
) -> Tuple[int, str, str]:
    """Run a command without a shell; never raises on non-zero exit."""
    if not args:
        return (1, "", "empty command")
    try:
        proc = subprocess.run(
            list(args),
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            check=False,
        )
        return (proc.returncode, proc.stdout or "", proc.stderr or "")
    except FileNotFoundError:
        return (127, "", f"command not found: {args[0]}")
    except subprocess.TimeoutExpired:
        return (124, "", f"timeout after {timeout}s: {args[0]}")
    except Exception as exc:  # pragma: no cover - defensive
        return (1, "", str(exc))


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------


def sort_ips(values: Iterable[str]) -> List[str]:
    import ipaddress

    def key(value: str):
        try:
            return (0, int(ipaddress.ip_address(value)))
        except ValueError:
            return (1, 0)

    return sorted({v for v in values if v}, key=key)


def format_table(rows: List[Tuple[str, object]], indent: str = "  ") -> str:
    if not rows:
        return ""
    width = max(len(str(r[0])) for r in rows)
    lines = []
    for label, value in rows:
        lines.append(f"{indent}{Colors.grey(str(label).ljust(width))}  {value}")
    return "\n".join(lines)


def truncate(text: str, limit: int = 100) -> str:
    text = _collapse(text)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def load_wordlist(path: str | Path) -> List[str]:
    words = []
    for line in read_lines(path):
        if line.startswith("#"):
            continue
        words.append(line.strip())
    return dedupe(words)

def url_host(url: str) -> str:
    """Return the lower-cased hostname of *url* (empty string when invalid)."""
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""
