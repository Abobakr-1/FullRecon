"""Configuration defaults for FullRecon.

Every value can be overridden by a JSON config file (``--config``), by a
per-user config at ``~/.config/fullrecon/config.json``, or by CLI flags.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 FullRecon/1.0"
)

# Directory numbering mirrors the documented output layout.
OUTPUT_DIRS = {
    "subdomains": "01-Subdomains",
    "dns": "02-DNS",
    "live": "03-Live-Hosts",
    "ports": "04-Ports",
    "technologies": "05-Technologies",
    "urls": "06-URLs",
    "api": "07-API",
    "javascript": "08-JavaScript",
    "content": "09-Content-Discovery",
    "whois": "10-WHOIS",
    "asn": "11-ASN",
    "headers": "12-Headers",
    "waf": "13-WAF",
    "wordpress": "14-WordPress",
    "reports": "15-Reports",
    "logs": "logs",
    "raw": "raw",
}

# Ports scanned by default, ordered by real-world frequency (nmap top-100
# style). Order matters: --top-ports N takes the first N entries.
DEFAULT_PORTS = [
    80, 443, 22, 21, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723,
    111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
    10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554, 26, 1433, 49152,
    2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631, 631, 49153, 8081,
    2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990, 5357, 427,
    49156, 543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070,
    5190, 3000, 5432, 3986, 13, 1029, 9, 6646, 49157, 1028, 873, 1755, 2717,
    4899, 9100, 119, 37, 6379, 9200, 27017, 5601, 2375, 7001, 9090, 9443, 11211,
]

# Ports that frequently run HTTP services (used as scheme/port hints).
HTTP_PORTS = {80, 81, 3000, 5000, 7001, 8000, 8008, 8080, 8081, 8088, 8888, 9000, 9090, 9200, 10000}
HTTPS_PORTS = {443, 8443, 9443}

INTERESTING_KEYWORDS = [
    "admin", "administrator", "login", "signin", "auth", "dashboard", "portal",
    "api", "graphql", "swagger", "openapi", "token", "oauth", "upload", "file",
    "download", "backup", "backups", "db", "database", "sql", "dump", "config",
    "configuration", "conf", "env", ".env", "secret", "secrets", "private",
    "internal", "staging", "stage", "dev", "test", "testing", "qa", "uat",
    "debug", "trace", "console", "phpinfo", "actuator", "metrics", "health",
    "jenkins", "gitlab", "jira", "confluence", "kibana", "grafana", "phpmyadmin",
    "wp-admin", "wp-json", "xmlrpc", "server-status", "swagger-ui", "docs",
    "redoc", "graphiql", "sso", "oauth2", "v1", "v2", "v3", "export", "invoice",
    "payment", "billing", "user", "users", "account", "accounts", "profile",
]

# File extensions that commonly leak sensitive data when directly reachable.
SENSITIVE_EXTENSIONS = [
    ".env", ".bak", ".backup", ".old", ".orig", ".save", ".swp", ".tmp",
    ".sql", ".db", ".sqlite", ".sqlite3", ".mdb", ".dump", ".tar", ".tar.gz",
    ".tgz", ".zip", ".rar", ".7z", ".gz", ".log", ".ini", ".cfg", ".conf",
    ".config", ".yml", ".yaml", ".json", ".xml", ".pem", ".key", ".p12",
    ".pfx", ".jks", ".htaccess", ".htpasswd", ".DS_Store", ".git/config",
]


@dataclass
class Config:
    """Runtime configuration for a single scan."""

    # ---- target / run -------------------------------------------------
    domain: str = ""
    out_dir: str = "FullRecon-Results"
    timestamped: bool = False
    overwrite: bool = False
    threads: int = 15
    rate_limit: float = 20.0          # max requests/second per host
    timeout: float = 10.0
    retries: int = 1
    user_agent: str = USER_AGENT
    proxy: Optional[str] = None
    verify_tls: bool = False          # recon targets often use self-signed certs
    user_agent_header: bool = True

    # ---- module selection ---------------------------------------------
    passive_only: bool = False
    active_only: bool = False

    # ---- subdomains ----------------------------------------------------
    subdomain_sources: List[str] = field(default_factory=lambda: [
        "crtsh", "certspotter", "hackertarget", "subdomain_center",
        "urlscan", "rapiddns", "otx", "wayback", "commoncrawl",
    ])
    subdomain_bruteforce: bool = False
    subdomain_wordlist: Optional[str] = None
    max_subdomains: int = 5000

    # ---- dns -----------------------------------------------------------
    dns_resolvers: List[str] = field(default_factory=list)   # empty = system
    dns_threads: int = 20
    resolve_subdomains: bool = True

    # ---- live hosts ----------------------------------------------------
    live_ports: List[int] = field(default_factory=lambda: [80, 443])
    verify_status: bool = True
    max_live_hosts: int = 2000

    # ---- ports ---------------------------------------------------------
    ports: List[int] = field(default_factory=lambda: list(DEFAULT_PORTS))
    port_scan_top: int = 100
    port_scan_timeout: float = 2.0
    port_scan_threads: int = 100
    use_nmap: bool = True
    nmap_service_detection: bool = True

    # ---- crawling / urls ------------------------------------------------
    crawl_depth: int = 2
    crawl_max_pages: int = 200
    crawl_max_urls: int = 20000
    wayback_urls: bool = True
    commoncrawl_urls: bool = True
    url_timeout: float = 10.0

    # ---- javascript ------------------------------------------------------
    js_max_files: int = 150
    js_max_size: int = 5 * 1024 * 1024

    # ---- content discovery -----------------------------------------------
    content_discovery: bool = True
    content_wordlist: Optional[str] = None
    content_extensions: List[str] = field(default_factory=lambda: [
        "", "php", "asp", "aspx", "jsp", "json", "txt", "xml", "bak", "old",
        "zip", "env", "config", "sql", "log",
    ])
    content_max_paths: int = 600
    content_ignore_status: List[int] = field(default_factory=lambda: [404])

    # ---- scope -------------------------------------------------------------
    scope: Dict[str, Any] = field(default_factory=dict)

    # ---- external tool integrations ------------------------------------------
    use_external_tools: bool = True        # drive subfinder/katana/gau/... if present
    subfinder_enabled: bool = True
    assetfinder_enabled: bool = True
    katana_enabled: bool = True
    gau_enabled: bool = True
    httpx_enabled: bool = False            # httpx replaces native probing; opt-in
    ffuf_enabled: bool = False             # ffuf replaces native content discovery
    katana_depth: int = 3
    external_tool_timeout: float = 240.0

    # ---- waf -----------------------------------------------------------------
    waf_probes: bool = True                # send benign blocking probes
    # ---- wordpress ------------------------------------------------------------
    wordpress_enabled: bool = True
    # ---- whois ----------------------------------------------------------------
    whois_enabled: bool = True
    # ---- asn -------------------------------------------------------------------
    asn_enabled: bool = True

    # ---- reporting ----------------------------------------------------------
    report_title: str = "FullRecon Report"
    open_report: bool = False

    # ------------------------------------------------------------------
    def resolved(self) -> "Config":
        """Normalise paths and scope relative to the working directory."""
        if self.scope is None:
            self.scope = {}
        self.scope.setdefault("in_scope", [])
        self.scope.setdefault("out_of_scope", [])
        self.scope.setdefault("allowed_ports", [])
        return self

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})

    @classmethod
    def load_file(cls, path: str) -> "Config":
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise ValueError("config file must contain a JSON object")
        return cls.from_dict(data)


def default_config_path() -> Optional[str]:
    """Return the per-user config path if the file exists."""
    candidates = []
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        candidates.append(Path(xdg) / "fullrecon" / "config.json")
    candidates.append(Path.home() / ".config" / "fullrecon" / "config.json")
    candidates.append(Path.home() / ".fullrecon.json")
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return None


def merge(base: Config, override: Config) -> Config:
    """Merge *override* into *base*, keeping base values for unset fields."""
    merged = base.to_dict()
    for key, value in override.to_dict().items():
        default_value = getattr(Config(), key, None)
        if value != default_value:
            merged[key] = value
    return Config.from_dict(merged)