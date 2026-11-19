"""Tests for scope enforcement and the passive-source allowlist."""

from __future__ import annotations

import pytest

from fullrecon.core.scanner import _is_external_source_host
from fullrecon.core.scope import Scope


def test_default_scope_allows_domain_and_subdomains():
    scope = Scope("example.com")
    assert scope.allows_host("example.com").allowed
    assert scope.allows_host("a.b.example.com").allowed
    assert not scope.allows_host("evil.com").allowed
    assert not scope.allows_host("example.com.evil.com").allowed


def test_out_of_scope_wins():
    scope = Scope("example.com", out_of_scope=["dev.example.com"])
    assert not scope.allows_host("dev.example.com").allowed
    assert scope.allows_host("app.example.com").allowed


def test_in_scope_extra_domain_and_cidr():
    scope = Scope("example.com", in_scope=["partner.net", "10.0.0.0/30"])
    assert scope.allows_host("www.partner.net").allowed
    assert scope.allows_host("10.0.0.2").allowed
    assert not scope.allows_host("10.0.0.9").allowed


def test_port_restrictions():
    scope = Scope("example.com", allowed_ports=[80, 443])
    assert scope.allows_port(80).allowed
    assert not scope.allows_port(8080).allowed
    assert scope.allows_url("https://example.com/").allowed
    assert not scope.allows_url("http://example.com:8080/").allowed


def test_url_scheme_restriction():
    scope = Scope("example.com")
    assert not scope.allows_url("ftp://example.com/x").allowed
    assert not scope.allows_url("javascript:alert(1)").allowed


def test_scope_file(tmp_path):
    path = tmp_path / "scope.txt"
    path.write_text(
        "# comment\n"
        "example.com\n"
        "assets.partner.net\n"
        "!staging.example.com\n"
        "192.0.2.0/24\n",
        encoding="utf-8",
    )
    scope = Scope("example.com", scope_file=str(path))
    assert scope.allows_host("www.example.com").allowed
    assert scope.allows_host("assets.partner.net").allowed
    assert not scope.allows_host("staging.example.com").allowed
    assert scope.allows_host("192.0.2.7").allowed


def test_filter_hosts_dedupes_and_filters():
    scope = Scope("example.com")
    hosts = ["a.example.com", "A.EXAMPLE.COM", "evil.com", "b.example.com"]
    assert scope.filter_hosts(hosts) == ["a.example.com", "b.example.com"]


@pytest.mark.parametrize("url,allowed", [
    ("https://crt.sh/?q=x", True),
    ("https://api.certspotter.com/v1/x", True),
    ("https://index.commoncrawl.org/CC-MAIN-2024-index?url=x", True),
    ("https://evil.com/crt.sh", False),
    ("https://crt.sh.evil.com/", False),
    ("https://example.com/", False),
])
def test_external_source_allowlist(url, allowed):
    from urllib.parse import urlsplit

    assert _is_external_source_host(urlsplit(url).hostname) is allowed