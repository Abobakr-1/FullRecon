"""Adapters for optional external recon binaries.

Every adapter follows the same contract:

* it never raises for a missing binary or a failing subprocess,
* it returns a :class:`ToolResult` recording what actually happened,
* callers fall back to the native Python implementation when ``ok`` is false.

This keeps FullRecon useful on a bare Kali install (``dnspython`` only) while
still letting a fully equipped machine use ProjectDiscovery tooling.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

from ..utils.helpers import dedupe


@dataclass
class ToolResult:
    """Outcome of one external-tool invocation."""

    tool: str
    available: bool = False
    ok: bool = False
    items: List[str] = field(default_factory=list)
    error: str = ""
    skipped_reason: str = ""
    duration: float = 0.0
    raw: str = ""
    extra: Dict[str, object] = field(default_factory=dict)

    def __bool__(self) -> bool:  # pragma: no cover - convenience
        return self.ok

    @property
    def count(self) -> int:
        return len(self.items)


# Tools FullRecon knows how to drive, with the purpose of each.
TOOL_REGISTRY: Dict[str, str] = {
    "subfinder": "passive subdomain enumeration (many sources)",
    "assetfinder": "related domain and subdomain discovery",
    "dnsx": "bulk DNS resolution and record probing",
    "httpx": "bulk HTTP probing, titles and tech detection",
    "katana": "crawling with JavaScript parsing",
    "gau": "URLs from AlienVault/Common Crawl/URLScan",
    "waybackurls": "URLs from the Wayback Machine",
    "ffuf": "content and vhost fuzzing",
    "nmap": "port and service detection",
    "whatweb": "technology fingerprinting",
    "wafw00f": "WAF detection",
    "wpscan": "WordPress enumeration",
    "amass": "in-depth subdomain enumeration",
    "nuclei": "template-based checks (never run automatically)",
}


def tool_path(name: str) -> Optional[str]:
    """Absolute path to *name* if it is executable, else ``None``."""
    return shutil.which(name)


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def available_tools() -> Dict[str, str]:
    """Map of installed tool name -> path."""
    found: Dict[str, str] = {}
    for name in TOOL_REGISTRY:
        path = shutil.which(name)
        if path:
            found[name] = path
    return found


def missing_tools() -> List[str]:
    return [name for name in TOOL_REGISTRY if shutil.which(name) is None]


def run_tool(
    tool: str,
    args: Sequence[str],
    timeout: float = 300.0,
    stdin_text: Optional[str] = None,
    cwd: Optional[str] = None,
    env_extra: Optional[Dict[str, str]] = None,
) -> ToolResult:
    """Execute *tool* with *args*; never raises.

    The binary is resolved through ``PATH`` so a hostile ``./subfinder`` in the
    scan directory cannot be executed by accident.
    """
    resolved = shutil.which(tool)
    if not resolved:
        return ToolResult(tool=tool, available=False,
                          skipped_reason=f"{tool} is not installed")

    env = dict(os.environ)
    env.setdefault("NO_COLOR", "1")
    if env_extra:
        env.update(env_extra)

    started = time.time()
    try:
        proc = subprocess.run(
            [resolved, *args],
            input=stdin_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=env,
            check=False,
            encoding="utf-8",
            errors="replace",
        )
        duration = time.time() - started
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        if proc.returncode != 0 and not stdout.strip():
            return ToolResult(
                tool=tool, available=True, ok=False,
                error=(stderr.strip() or f"exit {proc.returncode}")[:300],
                duration=duration,
            )
        return ToolResult(tool=tool, available=True, ok=True,
                          raw=stdout, duration=duration)
    except subprocess.TimeoutExpired:
        return ToolResult(tool=tool, available=True, ok=False,
                          error=f"timed out after {timeout:g}s",
                          duration=time.time() - started)
    except Exception as exc:  # noqa: BLE001 - adapters must not crash the scan
        return ToolResult(tool=tool, available=True, ok=False,
                          error=f"{type(exc).__name__}: {exc}",
                          duration=time.time() - started)


def _lines(text: str) -> List[str]:
    return dedupe([line.strip() for line in (text or "").splitlines()])


def _json_lines(text: str) -> List[dict]:
    out: List[dict] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


# ---------------------------------------------------------------------------
# Concrete adapters
# ---------------------------------------------------------------------------


def subfinder(
    domain: str,
    all_sources: bool = True,
    recursive: bool = False,
    timeout: float = 240.0,
    extra_args: Optional[Sequence[str]] = None,
) -> ToolResult:
    """Passive subdomains via ``subfinder``."""
    args = ["-d", domain, "-silent"]
    if all_sources:
        args.append("-all")
    if recursive:
        args.append("-recursive")
    if extra_args:
        args.extend(extra_args)
    result = run_tool("subfinder", args, timeout=timeout)
    if result.ok:
        result.items = [
            name.lower().rstrip(".")
            for name in _lines(result.raw)
            if name and "." in name and not name.startswith("#")
        ]
    return result


def assetfinder(domain: str, timeout: float = 120.0) -> ToolResult:
    """Related domains via ``assetfinder --subs-only``."""
    result = run_tool("assetfinder", ["--subs-only", domain], timeout=timeout)
    if result.ok:
        result.items = [
            name.lower().rstrip(".")
            for name in _lines(result.raw)
            if name and "." in name
        ]
    return result


def dnsx(hosts: Iterable[str], timeout: float = 240.0) -> ToolResult:
    """Resolve hostnames; returns the hosts that responded."""
    host_list = dedupe(list(hosts))
    if not host_list:
        return ToolResult(tool="dnsx", available=tool_available("dnsx"),
                          skipped_reason="no hosts supplied")
    result = run_tool("dnsx", ["-silent", "-a"], timeout=timeout,
                      stdin_text="\n".join(host_list))
    if result.ok:
        result.items = _lines(result.raw)
    return result


def httpx(urls: Iterable[str], timeout: float = 300.0,
          tech_detect: bool = True) -> ToolResult:
    """Probe URLs; ``extra['parsed']`` holds the decoded JSON objects."""
    url_list = dedupe(list(urls))
    if not url_list:
        return ToolResult(tool="httpx", available=tool_available("httpx"),
                          skipped_reason="no URLs supplied")
    args = ["-silent", "-json", "-follow-redirects", "-no-color"]
    if tech_detect:
        args.append("-tech-detect")
    result = run_tool("httpx", args, timeout=timeout,
                      stdin_text="\n".join(url_list))
    if result.ok:
        parsed = _json_lines(result.raw)
        result.extra["parsed"] = parsed
        result.items = [
            entry.get("url", "") for entry in parsed if entry.get("url")
        ]
    return result


def katana(
    url: str,
    depth: int = 3,
    js_crawl: bool = True,
    known_files: str = "all",
    timeout: float = 300.0,
) -> ToolResult:
    """Crawl with ``katana``; returns discovered URLs."""
    args = ["-u", url, "-silent", "-d", str(depth), "-no-color"]
    if js_crawl:
        args.append("-jc")
    if known_files:
        args.extend(["-kf", known_files])
    result = run_tool("katana", args, timeout=timeout)
    if result.ok:
        result.items = [
            line for line in _lines(result.raw)
            if line.startswith(("http://", "https://"))
        ]
    return result


def gau(domain: str, timeout: float = 180.0) -> ToolResult:
    """Historical URLs from ``gau``."""
    result = run_tool("gau", [domain, "--threads", "5"], timeout=timeout)
    if result.ok:
        result.items = [
            line for line in _lines(result.raw)
            if line.startswith(("http://", "https://"))
        ]
    return result


def waybackurls(domain: str, timeout: float = 180.0) -> ToolResult:
    """Historical URLs from ``waybackurls``."""
    result = run_tool("waybackurls", [domain], timeout=timeout,
                      stdin_text=domain)
    if result.ok:
        result.items = [
            line for line in _lines(result.raw)
            if line.startswith(("http://", "https://"))
        ]
    return result


def ffuf(
    url_template: str,
    wordlist: str,
    timeout: float = 600.0,
    extra_args: Optional[Sequence[str]] = None,
    rate: int = 40,
) -> ToolResult:
    """Run ``ffuf`` against a ``FUZZ`` template; returns matching URLs."""
    if not Path(wordlist).is_file():
        return ToolResult(tool="ffuf", available=tool_available("ffuf"),
                          skipped_reason=f"wordlist not found: {wordlist}")
    workdir = Path(tempfile.mkdtemp(prefix="fullrecon-ffuf-"))
    out_file = workdir / "out.json"
    args = [
        "-u", url_template,
        "-w", wordlist,
        "-of", "json",
        "-o", str(out_file),
        "-s",
        "-rate", str(rate),
        "-mc", "200,201,202,204,301,302,307,401,403,405,500",
    ]
    if extra_args:
        args.extend(extra_args)
    result = run_tool("ffuf", args, timeout=timeout)
    if result.ok and out_file.is_file():
        try:
            data = json.loads(out_file.read_text(encoding="utf-8", errors="replace"))
            result.items = [
                entry.get("url", "")
                for entry in data.get("results", [])
                if entry.get("url")
            ]
        except (json.JSONDecodeError, OSError):
            result.items = []
    return result


def nmap_services(hosts: Iterable[str], ports: Optional[Sequence[int]] = None,
                  timeout: float = 900.0) -> ToolResult:
    """``nmap -sV`` against the supplied hosts."""
    host_list = dedupe(list(hosts))
    if not host_list:
        return ToolResult(tool="nmap", available=tool_available("nmap"),
                          skipped_reason="no hosts supplied")
    args = ["-Pn", "-sV", "--version-light", "--host-timeout", "300s", "-T4"]
    if ports:
        args.extend(["-p", ",".join(str(p) for p in ports)])
    result = run_tool("nmap", [*args, *host_list], timeout=timeout)
    if result.ok:
        result.items = [
            line.strip() for line in result.raw.splitlines()
            if "/tcp" in line and "open" in line.split()
        ]
    return result


def whatweb(urls: Iterable[str], timeout: float = 300.0) -> ToolResult:
    """Technology fingerprinting via ``whatweb``."""
    url_list = dedupe(list(urls))
    if not url_list:
        return ToolResult(tool="whatweb", available=tool_available("whatweb"),
                          skipped_reason="no URLs supplied")
    workdir = Path(tempfile.mkdtemp(prefix="fullrecon-whatweb-"))
    out_file = workdir / "out.json"
    result = run_tool(
        "whatweb",
        ["--log-json", str(out_file), "--no-errors", "-q"],
        timeout=timeout,
        stdin_text="\n".join(url_list),
    )
    entries: List[str] = []
    if out_file.is_file():
        try:
            for line in out_file.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line.startswith("{"):
                    entries.append(line)
        except OSError:
            pass
    if entries:
        result.ok = True
        result.items = entries
    return result


def wafw00f(url: str, timeout: float = 120.0) -> ToolResult:
    """WAF detection via ``wafw00f``."""
    result = run_tool("wafw00f", [url, "-a", "-f", "json"], timeout=timeout)
    if result.ok:
        detected = []
        for line in result.raw.splitlines():
            match = re.search(r'"firewall":\s*"([^"]+)"', line)
            if match and match.group(1).lower() not in ("none", "generic"):
                detected.append(match.group(1))
        result.items = dedupe(detected)
    return result


def wpscan(url: str, timeout: float = 600.0,
           api_token: Optional[str] = None) -> ToolResult:
    """WordPress enumeration via ``wpscan`` (WordPress targets only)."""
    args = ["--url", url, "--enumerate", "vp,vt,u", "--no-banner",
            "--random-user-agent", "--format", "json", "--no-update",
            "--disable-tls-checks"]
    if api_token:
        args.extend(["--api-token", api_token])
    result = run_tool("wpscan", args, timeout=timeout)
    if result.ok and result.raw.strip().startswith("{"):
        result.items = [result.raw]
    return result


def amass_intel_org(org: str, timeout: float = 600.0) -> ToolResult:
    """Organisation-to-domain discovery via ``amass intel -org``."""
    result = run_tool("amass", ["intel", "-org", org, "-silent"], timeout=timeout)
    if result.ok:
        result.items = [line for line in _lines(result.raw) if "." in line]
    return result


def amass_intel_asn(asn: str, timeout: float = 600.0) -> ToolResult:
    """ASN-to-CIDR discovery via ``amass intel -asn``."""
    result = run_tool("amass", ["intel", "-asn", asn, "-silent"], timeout=timeout)
    if result.ok:
        result.items = _lines(result.raw)
    return result


def summary() -> Dict[str, object]:
    """Tool availability report used by ``--check-tools`` and the report."""
    return {
        "installed": available_tools(),
        "missing": missing_tools(),
        "registry": TOOL_REGISTRY,
    }