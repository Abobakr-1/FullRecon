"""Offline module tests using a fake HTTP client (no network access)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fullrecon.config import Config
from fullrecon.core.context import ModuleContext, ReconState
from fullrecon.core.output_manager import OutputManager
from fullrecon.core.scope import Scope
from fullrecon.core.scanner import Response
from fullrecon.modules.dns import DnsModule
from fullrecon.modules.javascript import JavaScriptModule, _looks_like_placeholder, _redact
from fullrecon.modules.subdomains import SubdomainModule
from fullrecon.modules.technologies import COMPILED, TechnologyModule


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class FakeHttp:
    """Deterministic stand-in for HttpClient."""

    def __init__(self, routes=None, default_status=404):
        self.routes = routes or {}
        self.default_status = default_status
        self.requests = []

    def get(self, url, **kwargs):
        self.requests.append(url)
        for pattern, response in self.routes.items():
            if pattern in url:
                return response(url) if callable(response) else response
        return Response(url=url, status=self.default_status, body="", headers={})

    def head(self, url, **kwargs):
        return self.get(url, **kwargs)

    def post(self, url, **kwargs):
        return self.get(url, **kwargs)


def make_ctx(tmp_path, domain="example.com", http=None, **cfg_kwargs):
    cfg = Config(domain=domain, out_dir=str(tmp_path / "out"), **cfg_kwargs)
    cfg.resolved()
    scope = Scope(
        domain,
        in_scope=cfg.scope.get("in_scope") or [],
        out_of_scope=cfg.scope.get("out_of_scope") or [],
    )
    out = OutputManager(cfg)
    out.prepare()
    state = ReconState(target=domain)
    ctx = ModuleContext(cfg, scope, http or FakeHttp(), out, state)
    return ctx, state, out


def html_response(url, body, status=200, headers=None):
    hdrs = {"content-type": "text/html; charset=utf-8"}
    hdrs.update(headers or {})
    return Response(url=url, status=status, headers=hdrs, body=body, redirect_chain=[url])


# ---------------------------------------------------------------------------
# Subdomains
# ---------------------------------------------------------------------------


def test_subdomain_normalise_filters_off_domain(tmp_path):
    ctx, _, _ = make_ctx(tmp_path)
    module = SubdomainModule(ctx)
    raw = [
        "www.example.com", "*.api.example.com", "WWW.Example.COM.",
        "example.com.evil.net", "evil.net", "example.com", "a_b.example.com",
    ]
    cleaned = module._normalise(raw, "example.com")
    assert "www.example.com" in cleaned
    assert "example.com" in cleaned
    assert "example.com.evil.net" not in cleaned
    assert "evil.net" not in cleaned
    assert len(cleaned) == len(set(cleaned))


def test_subdomain_sources_parse_shapes(tmp_path, monkeypatch):
    from fullrecon.modules.subdomains import Sources

    ctx, _, _ = make_ctx(tmp_path)
    sources = Sources(ctx)

    monkeypatch.setattr(sources, "_json", lambda url, headers=None: [
        {"name_value": "a.example.com\n*.b.example.com", "common_name": "c.example.com"}
    ])
    out = sources.crtsh("example.com")
    assert {"a.example.com", "b.example.com", "c.example.com"} <= set(out)

    monkeypatch.setattr(sources, "_json", lambda url, headers=None: [
        {"dns_names": ["x.example.com", "*.y.example.com"]}
    ])
    assert sources.certspotter("example.com") == ["x.example.com", "y.example.com"]

    monkeypatch.setattr(
        sources, "_get",
        lambda *a, **k: Response(url="u", status=200,
                                 body="a.example.com,1.2.3.4\nb.example.com,5.6.7.8\n"),
    )
    assert sources.hackertarget("example.com") == ["a.example.com", "b.example.com"]

    monkeypatch.setattr(sources, "_json", lambda url, headers=None: [])  # malformed -> no crash
    assert sources.subdomain_center("example.com") == []


def test_subdomain_source_failure_is_isolated(tmp_path, monkeypatch):
    ctx, state, _ = make_ctx(tmp_path)
    module = SubdomainModule(ctx)

    def boom(domain):
        raise RuntimeError("API down")

    module.source_map = {"crtsh": boom}
    ctx.cfg.subdomain_sources = ["crtsh"]
    monkeypatch.setattr(module, "_validate", lambda hosts, domain: (hosts, [], {}))
    result = module.run()
    assert result["unique"] >= 1
    assert any("API down" in e for e in state.errors)


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cname,expected", [
    ("mybucket.s3.amazonaws.com", True),
    ("app.herokuapp.com", True),
    ("site.github.io", True),
    ("something.azurewebsites.net", True),
    ("www.cloudflare.com", False),
    ("", False),
])
def test_takeover_fingerprints(cname, expected):
    assert bool(DnsModule._takeover_reason(cname)) is expected


def test_dns_writes_expected_files(tmp_path, monkeypatch):
    ctx, state, out = make_ctx(tmp_path)
    module = DnsModule(ctx)

    monkeypatch.setattr(module, "enumerate_host", lambda host: {
        "A": ["93.184.216.34"],
        "CNAME": ["dead.s3.amazonaws.com"] if host == "old.example.com" else [],
        "TXT": ["v=spf1 -all"] if host == "example.com" else [],
        "MX": ["10 mail.example.com"] if host == "example.com" else [],
    })
    state.resolved_subdomains = ["example.com", "old.example.com"]
    module.run()

    assert len(state.dangling_cnames) == 1
    assert state.dangling_cnames[0]["host"] == "old.example.com"
    base = out.dir("dns")
    assert "old.example.com" in (base / "dangling_cnames.txt").read_text(encoding="utf-8")
    assert any("v=spf1" in line for line in state.interesting_dns)
    assert "93.184.216.34" in (base / "dns_records.txt").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Technology detection
# ---------------------------------------------------------------------------


def test_technology_detection_from_headers_and_body(tmp_path):
    body = (
        '<html><head><meta name="generator" content="WordPress 6.4">'
        '<script src="/wp-includes/js/jquery/jquery.min.js"></script>'
        '<script src="/static/react-dom.production.min.js"></script>'
        '</head><body><div id="__NEXT_DATA__"></div></body></html>'
    )
    resp = html_response("https://example.com/", body, headers={
        "server": "nginx/1.24.0", "x-powered-by": "PHP/8.2.1",
        "set-cookie": "laravel_session=abc",
    })
    ctx, _, _ = make_ctx(tmp_path, http=FakeHttp({"example.com": resp}))
    found = TechnologyModule(ctx).detect("https://example.com/")
    names = set(found)
    for expected in ("Nginx", "PHP", "WordPress", "Laravel", "Next.js", "React", "jQuery"):
        assert expected in names, f"{expected} not detected in {sorted(names)}"
    assert found["Nginx"]["version"] == "1.24.0"
    assert found["WordPress"]["version"] == "6.4"


def test_technology_signatures_compile():
    assert len(COMPILED) > 40
    assert all(len(entry) == 4 for entry in COMPILED)


def test_technology_returns_empty_on_failed_request(tmp_path):
    ctx, _, _ = make_ctx(tmp_path, http=FakeHttp({}, default_status=0))
    assert TechnologyModule(ctx).detect("https://example.com/") == {}


# ---------------------------------------------------------------------------
# JavaScript
# ---------------------------------------------------------------------------


def test_javascript_secret_and_endpoint_extraction(tmp_path):
    js = """
    const cfg = { apiKey: "AKIA7QZ3WX5PLKJ2HGFD", baseURL: "/api/v1/users" };
    fetch("/api/v2/orders?limit=10");
    axios.get("https://example.com/internal/audit");
    // TODO: remove the debug token before release
    window.__ENV__.SECRET_URL = "https://example.com/x";
    """
    ctx, state, out = make_ctx(tmp_path, http=FakeHttp({
        "app.js": Response(url="https://example.com/app.js", status=200,
                           headers={"content-type": "application/javascript"}, body=js),
    }))
    state.js_files = ["https://example.com/app.js"]
    result = JavaScriptModule(ctx).run()

    assert result["js_files"] == 1
    assert any("/api/v2/orders" in e for e in state.js_endpoints)
    assert any("/internal/audit" in e for e in state.js_endpoints)
    assert state.js_secrets, "expected at least one secret pattern"
    assert all("[len=" in s["value_redacted"] for s in state.js_secrets)
    assert not any("AKIA7QZ3WX5PLKJ2HGFD" in s["value_redacted"] for s in state.js_secrets)
    assert state.js_comments
    exposures = (out.dir("javascript") / "potential_exposures.txt").read_text(encoding="utf-8")
    assert "AKIA7QZ3WX5PLKJ2HGFD" not in exposures


def test_placeholder_and_redaction_helpers():
    assert _looks_like_placeholder("your_api_key_here")
    assert _looks_like_placeholder("xxxxxxxxxxxxxxxx")
    assert not _looks_like_placeholder("aB3dE5fG7hI9jK1lM3nO5p")
    assert "..." in _redact("abcdefghijklmnop")
    assert _redact("short") == "*****"


def test_javascript_ignores_out_of_scope_files(tmp_path):
    ctx, state, _ = make_ctx(tmp_path)
    state.js_files = ["https://evil.com/app.js"]
    assert JavaScriptModule(ctx).run()["js_files"] == 0