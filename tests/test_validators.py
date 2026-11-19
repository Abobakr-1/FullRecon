"""Tests for target validation and normalisation."""

from __future__ import annotations

import pytest

from fullrecon.utils.validators import (
    ValidationError,
    in_domain,
    is_domain,
    is_ip,
    is_private_ip,
    is_url,
    is_valid_hostname,
    normalise_target,
    same_site,
    split_host_port,
    url_host,
    validate_target,
)


@pytest.mark.parametrize("raw,expected", [
    ("example.com", "example.com"),
    ("  Example.COM  ", "example.com"),
    ("https://example.com/path?x=1", "example.com"),
    ("http://user:pass@sub.example.com:8080/a", "sub.example.com"),
    ("*.example.com", "example.com"),
    ("example.com.", "example.com"),
])
def test_normalise_target(raw, expected):
    assert normalise_target(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "localhost", "http://", "!!!", "not a domain"])
def test_validate_target_rejects_invalid(raw):
    with pytest.raises(ValidationError):
        validate_target(raw)


def test_validate_target_accepts_ip():
    assert validate_target("93.184.216.34") == "93.184.216.34"


@pytest.mark.parametrize("value,expected", [
    ("example.com", True),
    ("a.b.example.co.uk", True),
    ("example", False),
    ("exa mple.com", False),
    ("-bad.com", False),
    ("1234.5678", False),
    ("", False),
])
def test_is_domain(value, expected):
    assert is_domain(value) is expected


def test_ip_helpers():
    assert is_ip("10.0.0.1")
    assert is_ip("::1")
    assert not is_ip("example.com")
    assert is_private_ip("192.168.1.1")
    assert is_private_ip("127.0.0.1")
    assert not is_private_ip("93.184.216.34")


def test_in_domain():
    assert in_domain("a.example.com", "example.com")
    assert in_domain("example.com", "example.com")
    assert not in_domain("example.com.evil.net", "example.com")
    assert not in_domain("notexample.com", "example.com")
    assert not in_domain("", "example.com")


def test_is_valid_hostname():
    assert is_valid_hostname("a.b.example.com")
    assert is_valid_hostname("under_score.example.com")
    assert not is_valid_hostname("-bad.example.com")
    assert not is_valid_hostname("example.com:80")


def test_is_url():
    assert is_url("https://example.com")
    assert is_url("http://example.com:8080/x")
    assert not is_url("ftp://example.com")
    assert not is_url("example.com")


def test_split_host_port():
    assert split_host_port("example.com:8080") == ("example.com", 8080)
    assert split_host_port("example.com") == ("example.com", None)
    assert split_host_port("[::1]:443") == ("::1", 443)


def test_url_host():
    assert url_host("https://A.Example.com:8443/x") == "a.example.com"
    assert url_host("nonsense") == ""


def test_same_site():
    assert same_site("a.example.com", "b.example.com")
    assert same_site("a.example.co.uk", "b.example.co.uk")
    assert not same_site("example.com", "example.org")