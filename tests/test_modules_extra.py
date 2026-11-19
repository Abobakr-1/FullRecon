"""Offline tests for URL, API, content-discovery, port and intel modules."""

from __future__ import annotations

import json

import pytest

from fullrecon.core.portscan import PortResult, PortScanner
from fullrecon.core.scanner import Response
from fullrecon.modules.api import ApiModule, _looks_like_spec
from fullrecon.modules.content_discovery import ContentModule, _signature
from fullrecon.modules.intelligence import IntelligenceModule
from fullrecon.modules.portscan import PortScanModule
from fullrecon.modules.urls import UrlModule

from .test_modules import FakeHttp, html_response, make_ctx


# ---------------------------------------------------------------------------
# URL discovery
# ---------------------------------------------------------------------------


def test_url_module_dedupes_and_flags_interesting(tmp_path):
    page = (
        '<html><a href="/admin">a</a><a href="/about">b</a>'
        '<script src="/app.js"></script>'
        '<a href="https://evil.com/x">out</a></html>'
    )
    routes = {
        "robots.txt": Response(url="u", status=200, body="Disallow: /private\n"),
        "https://example.com/": html_response("https://example.com/", page),
    }
    ctx, state, _ = make_ctx(tmp_path, http=FakeHttp(routes, default_status=404))
    ctx.cfg.crawl_max_pages = 3
    ctx.cfg.wayback_urls = False
    ctx.cfg.commoncrawl_urls = False

    UrlModule(ctx).run()
    urls = state.urls
    assert "https://example.com/admin" in urls
    assert "https://example.com/about" in urls
    assert all("evil.com" not in u for u in urls)
    assert len(urls) == len(set(urls))
    assert any("/admin" in u for u in state.interesting_urls)
    assert "https://example.com/app.js" in state.js_files
    assert any("/private" in u for u in urls)


def test_url_module_handles_no_seeds(tmp_path):
    ctx, state, _ = make_ctx(tmp_path, http=FakeHttp({}, default_status=404))
    ctx.cfg.wayback_urls = False
    ctx.cfg.commoncrawl_urls = False
    result = UrlModule(ctx).run()
    assert result["urls"] >= 0  # must not raise


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------


def test_api_spec_detection():
    assert _looks_like_spec('{"openapi": "3.0.0", "paths": {}}')
    assert _looks_like_spec('{"swagger": "2.0"}')
    assert _looks_like_spec("openapi: 3.0.0\npaths: {}")
    assert not _looks_like_spec('{"unrelated": true}')
    assert not _looks_like_spec("")


def test_api_harvests_endpoints_from_urls_and_js(tmp_path):
    routes = {
        "/openapi.json": Response(
            url="u", status=200, headers={"content-type": "application/json"},
            body='{"openapi":"3.0.0","paths":{}}',
        ),
        "/graphql": Response(
            url="u", status=400,
            body='{"errors":[{"message":"Must provide query string"}]}',
        ),
    }
    ctx, state, _ = make_ctx(tmp_path, http=FakeHttp(routes))
    state.live = [
        {"host": "example.com", "url": "https://example.com/", "final_url": "https://example.com/"}
    ]
    state.urls = [
        "https://example.com/api/v1/users/42",
        "https://example.com/rest/orders?id=7",
        "https://example.com/about",
    ]
    state.js_endpoints = ["https://example.com/graphql"]
    ctx.cfg.threads = 2

    ApiModule(ctx).run()
    assert any("/openapi.json" in e for e in state.swagger_endpoints)
    assert any("graphql" in e for e in state.graphql_endpoints)
    assert any("/api/v1/users/42" in e for e in state.api_endpoints)
    assert "id" in state.api_parameters


# ---------------------------------------------------------------------------
# Content discovery
# ---------------------------------------------------------------------------


def test_content_discovery_soft404_is_ignored(tmp_path):
    def responder(url, **kwargs):
        if "fullrecon-probe" in url:
            return html_response(url, "<html>custom not found page</html>", status=200)
        if url.endswith("/admin"):
            return html_response(url, "<html>admin</html>", status=403)
        return html_response(url, "<html>custom not found page</html>", status=200)

    ctx, state, _ = make_ctx(tmp_path, http=FakeHttp({}, default_status=200))
    ctx.http.get = responder
    ctx.cfg.threads = 4
    ctx.cfg.content_max_paths = 20
    state.live = [
        {"host": "example.com", "url": "https://example.com/", "final_url": "https://example.com/"}
    ]

    ContentModule(ctx).run()
    paths = {r["path"] for r in state.content}
    assert "admin" in paths
    assert len(paths) == 1, f"soft-404 filtering failed: {sorted(paths)[:10]}"
    assert any("admin" in str(f["url"]) for f in state.interesting_files)


def test_content_discovery_skipped_in_passive_mode(tmp_path):
    ctx, state, _ = make_ctx(tmp_path)
    ctx.passive = True
    assert ContentModule(ctx).run()["paths"] == 0


def test_signature_is_stable():
    a = _signature(200, {"content-type": "text/html"}, "hello world")
    b = _signature(200, {"content-type": "text/html"}, "hello world")
    c = _signature(200, {"content-type": "text/html"}, "different")
    assert a == b != c


# ---------------------------------------------------------------------------
# Ports
# ---------------------------------------------------------------------------


def test_parse_nmap_output():
    output = """
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for example.com (93.184.216.34)
Host is up (0.010s latency).
PORT    STATE SERVICE  VERSION
80/tcp  open  http     nginx 1.24.0
443/tcp open  ssl/http nginx 1.24.0
Nmap scan report for 93.184.216.34
PORT    STATE SERVICE VERSION
80/tcp  open  http    nginx 1.24.0
"""
    results = PortScanner._parse_nmap(output)
    assert len(results) == 3
    assert results[0].version.startswith("nginx")
    assert results[0].service == "http"


def test_port_merge_prefers_version_data():
    results = [
        PortResult(host="a", port=80),
        PortResult(host="a", port=80, version="nginx"),
        PortResult(host="a", port=443, service="https"),
    ]
    merged = PortScanner._merge(results)
    assert len(merged) == 2
    assert [r.version for r in merged if r.port == 80] == ["nginx"]


def test_unusual_ports_are_flagged_from_nmap_style_results(tmp_path):
    """Regression: nmap --open omits closed ports; flagging must use the port."""
    from fullrecon.core.portscan import PortResult

    ctx, state, out = make_ctx(tmp_path)
    results = [
        PortResult(host="scanme.nmap.org", port=22, service="ssh"),
        PortResult(host="scanme.nmap.org", port=80, service="http"),
    ]
    entries = []
    for item in PortScanner._merge(results):
        entry = item.to_dict()
        entry["web"] = False
        entry["unusual"] = __import__(
            "fullrecon.core.portscan", fromlist=["is_unusual"]
        ).is_unusual(item.port)
        entries.append(entry)
    assert [e["port"] for e in entries if e["unusual"]] == [22]


def test_port_module_excludes_out_of_scope_hosts(tmp_path):
    ctx, state, _ = make_ctx(tmp_path)
    ctx.cfg.ports = [80]
    ctx.cfg.use_nmap = False
    state.resolved_subdomains = ["example.com", "outside.invalid"]
    module = PortScanModule(ctx)
    assert module._targets() == ["example.com"]


def test_port_module_respects_allowed_ports(tmp_path):
    from fullrecon.core.scope import Scope

    ctx, state, _ = make_ctx(tmp_path)
    ctx.scope = Scope("example.com", allowed_ports=[443])
    ctx.cfg.ports = [80, 443]
    module = PortScanModule(ctx)
    assert module._ports() == [80, 443]  # module lists them...
    # ...but the engine filters through scope before connecting.
    assert not ctx.scope.allows_port(80).allowed
    assert ctx.scope.allows_port(443).allowed


# ---------------------------------------------------------------------------
# Intelligence
# ---------------------------------------------------------------------------


def test_intelligence_scoring(tmp_path):
    ctx, state, out = make_ctx(tmp_path)
    state.subdomains = {"src": ["dev.example.com", "example.com"]}
    state.dangling_cnames = [{
        "host": "old.example.com", "cname": "x.s3.amazonaws.com",
        "reason": "points at S3 bucket (s3.amazonaws.com)",
    }]
    state.ports = [
        {"host": "example.com", "port": 3306, "service": "mysql", "version": ""},
        {"host": "example.com", "port": 443, "service": "https", "version": ""},
    ]
    state.live = [
        {"host": "example.com", "url": "http://example.com/",
         "final_url": "http://example.com/", "scheme": "http", "status": 200,
         "title": "", "server": "nginx"},
        {"host": "example.com", "url": "https://example.com/",
         "final_url": "https://example.com/", "scheme": "https", "status": 200,
         "title": "", "server": "nginx"},
    ]
    state.js_secrets = [{
        "type": "AWS Access Key ID", "confidence": "high",
        "value_redacted": "AKIAI...MPLE", "length": "20", "source": "a.js",
    }]
    state.interesting_urls = ["https://example.com/admin?id=1"]

    IntelligenceModule(ctx).run()

    titles = [f["title"].lower() for f in state.findings]
    severities = {f["severity"] for f in state.findings}
    assert any("takeover" in t for t in titles)
    # MySQL (3306) must be reported as high-risk, not lumped with SSH.
    assert any("high-risk service" in t for t in titles)
    high_evidence = " ".join(
        str(item) for f in state.findings if f["severity"] == "high" for item in f["evidence"]
    )
    assert "3306" in high_evidence
    assert "high" in severities
    assert state.findings[0]["severity"] == "high"
    report = json.loads((out.dir("reports") / "findings.json").read_text(encoding="utf-8"))
    assert report["severity"]["high"] >= 1
    assert report["counts"]["live_hosts"] >= 1


def test_intelligence_empty_state_is_safe(tmp_path):
    ctx, state, _ = make_ctx(tmp_path)
    result = IntelligenceModule(ctx).run()
    assert result["findings"] == 0
    assert state.findings == []

# ---------------------------------------------------------------------------
# Live host discovery
# ---------------------------------------------------------------------------


def test_live_host_dedupes_default_ports(tmp_path):
    from fullrecon.core.context import ModuleContext
    from fullrecon.core.scope import Scope
    from fullrecon.modules.live_hosts import LiveHostModule

    class Always200:
        def get(self, url, **kwargs):
            return html_response(url, "<title>x</title>")

    ctx, state, _ = make_ctx(tmp_path, domain="a.com")
    ctx.http = Always200()
    state.resolved_subdomains = ["a.com"]
    # Port scanner reports :80, while the scheme-implied probe is also :80.
    state.ports = [{"host": "a.com", "port": 80, "service": "http"}]

    LiveHostModule(ctx).run()
    endpoints = [(e["scheme"], e["port"]) for e in state.live]
    assert endpoints.count(("http", 80)) == 1
    assert ("https", 443) in endpoints


def test_live_host_display_target_drops_implied_ports():
    from fullrecon.modules.live_hosts import LiveHostModule

    assert LiveHostModule._display_target("http", "a.com:80") == "a.com"
    assert LiveHostModule._display_target("https", "a.com:443") == "a.com"
    assert LiveHostModule._display_target("http", "a.com:8080") == "a.com:8080"
    assert LiveHostModule._display_target("http", "a.com") == "a.com"
