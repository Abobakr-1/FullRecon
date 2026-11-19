"""Validation helpers for targets, hostnames, URLs and IPs."""

from __future__ import annotations

import ipaddress
import re
from typing import Optional, Tuple
from urllib.parse import urlsplit

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9_-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*$"
)
_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9_]{1,63}(?<!-)$")


class ValidationError(ValueError):
    """Raised when a target or hostname fails validation."""


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def is_private_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value.strip("[]"))
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved


def is_domain(value: str) -> bool:
    if not value or len(value) > 253:
        return False
    value = value.rstrip(".")
    if is_ip(value):
        return False
    if not _DOMAIN_RE.match(value):
        return False
    labels = value.split(".")
    if len(labels) < 2:
        return False
    # TLD must not be numeric-only.
    if labels[-1].isdigit():
        return False
    return True


def normalise_target(raw: str) -> str:
    """Return a bare registered-domain-ish hostname from user input.

    Accepts ``example.com``, ``https://example.com/path``, ``*.example.com``,
    upper-case names and trailing dots.
    """
    if raw is None:
        raise ValidationError("target is required")
    value = raw.strip()
    if not value:
        raise ValidationError("target is empty")
    if "://" in value:
        parts = urlsplit(value)
        value = parts.hostname or ""
    value = value.split("/")[0].split("?")[0].split("#")[0]
    if "@" in value:
        value = value.rsplit("@", 1)[-1]
    if ":" in value and not is_ip(value):
        value = value.split(":")[0]
    value = value.strip().strip(".").lower()
    if value.startswith("*."):
        value = value[2:]
    if value.startswith("www.") and value.count(".") > 2:
        # keep www intact; it is a real hostname
        pass
    if not value:
        raise ValidationError("could not parse a hostname from the supplied target")
    return value


def validate_target(raw: str) -> str:
    """Normalise and strictly validate a scan target; raise ValidationError."""
    value = normalise_target(raw)
    if is_ip(value):
        return value
    if not is_domain(value):
        raise ValidationError(f"invalid domain name: {raw!r}")
    if len(value.split(".")) < 2:
        raise ValidationError(f"target must be a fully qualified domain: {raw!r}")
    return value


def is_valid_hostname(value: str) -> bool:
    value = (value or "").strip().rstrip(".")
    if not value or len(value) > 253:
        return False
    if is_ip(value):
        return True
    labels = value.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or not _LABEL_RE.match(label):
            return False
    return not labels[-1].isdigit()


def in_domain(host: str, domain: str) -> bool:
    """True when *host* equals *domain* or is a subdomain of it."""
    host = (host or "").strip().lower().rstrip(".")
    domain = (domain or "").strip().lower().rstrip(".")
    if not host or not domain:
        return False
    return host == domain or host.endswith("." + domain)


def is_url(value: str) -> bool:
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    return parts.scheme in ("http", "https") and bool(parts.hostname)


def split_host_port(value: str) -> Tuple[str, Optional[int]]:
    """Split ``host``, ``host:port`` or ``[v6]:port`` into (host, port)."""
    value = (value or "").strip()
    if value.startswith("["):
        end = value.find("]")
        if end != -1:
            host = value[1:end]
            rest = value[end + 1:]
            if rest.startswith(":"):
                try:
                    return host, int(rest[1:])
                except ValueError:
                    return host, None
            return host, None
    if value.count(":") == 1:
        host, _, port = value.partition(":")
        if port.isdigit():
            return host, int(port)
    return value, None


def url_host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def same_site(host_a: str, host_b: str) -> bool:
    """Loose eTLD+1 comparison that avoids a heavy dependency."""
    def root(host: str) -> str:
        labels = [l for l in (host or "").lower().split(".") if l]
        if len(labels) <= 2:
            return ".".join(labels)
        # Handle common two-part public suffixes.
        two_part = {"co.uk", "com.au", "co.jp", "com.br", "co.in", "com.cn",
                    "org.uk", "net.uk", "gov.uk", "ac.uk", "co.za", "com.sg",
                    "com.tr", "com.mx", "co.kr", "com.tw", "com.hk", "co.il"}
        if ".".join(labels[-2:]) in two_part and len(labels) >= 3:
            return ".".join(labels[-3:])
        return ".".join(labels[-2:])
    return root(host_a) == root(host_b)


def is_ip_target(target: str) -> bool:
    return is_ip(target)