"""Tests for the Recon & Mapping additions (offline, no network, no binaries)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fullrecon.core import tools
from fullrecon.core.scanner import Response
from fullrecon.modules.asn import AsnModule
from fullrecon.modules.headers import HEADER_RULES, HeadersModule
from fullrecon.modules.waf import BLOCK_STATUSES, PROBES, SIGNATURES, WafModule
from fullrecon.modules.whois import FALLBACK_RDAP, WhoisModule, _rdap_key
from fullrecon.modules.wordpress import (
    PLUGIN_RE,
    THEME_RE,
    VERSION_PATTERNS,
    WordPressModule,
)

from .test_modules import FakeHttp, html_response, make_ctx


# ---------------------------------------------------------------------------
# External tool adapter layer
# ---------------------------------------------------------------------------


def test_missing_tool_is_reported_not_raised():
    result = tools.run_tool("fullrecon-definitely-not-installed", ["--help"])
    assert result.ok is False
    assert result.available is False
    assert "not installed" in result.skipped_reason


def test_tool_result_contract_is_stable():
    result = tools.ToolResult(tool="x", ok=True, items=["a", "b"])
    assert bool(result) is True
    assert result.count == 2
    empty = tools.ToolResult(tool="y")
    assert bool(empty) is False
    assert empty.count == 0


def test_registry_covers_documented_tools():
    for name in ("subfinder", "assetfinder", "dnsx", "httpx", "katana",
                 "gau", "waybackurls", "ffuf", "nmap", "wafw00f", "wpscan"):
        assert name in tools.TOOL_REGISTRY
        assert tools.TOOL_REGISTRY[name]


def test_summary_structure():
    report = tools.summary()
    assert set(report) == {"installed", "missing", "registry"}
    assert isinstance(report["installed"], dict)
    assert isinstance(report["missing"], list)
    # Every tool is either installed or missing, never both.
    assert not (set(report["installed"]) & set(report["missing"]))


def test_ffuf_rejects_missing_wordlist():
    result = tools.ffuf("https://example.com/FUZZ", "/nonexistent/wordlist.txt")
    assert result.ok is False
    assert "wordlist" in result.skipped_reason


def test_adapters_handle_empty_input():
    for adapter in (tools.dnsx, tools.httpx, tools.whatweb, tools.nmap_services):
        result = adapter([])
        assert result.ok is False


# ---------------------------------------------------------------------------
# WHOIS / RDAP
# ---------------------------------------------------------------------------


def test_rdap_key_idna():
    assert _rdap_key("example.com") == "example.com"
    assert _rdap_key("EXAMPLE.COM") == "example.com"


def test_fallback_rdap_covers_major_tlds():
    for tld in ("com", "net", "org", "io", "uk", "de"):
        assert tld in FALLBACK_RDAP


RDAP_PAYLOAD = {
    "handle": "2336799_DOMAIN_COM-VRSN",
    "ldhName": "EXAMPLE.COM",
    "status": ["client transfer prohibited"],
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"},
    ],
    "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}, {"ldhName": "B.IANA-SERVERS.NET"}],
    "secureDNS": {"delegationSigned": False},
    "entities": [
        {
            "roles": ["registrar"],
            "handle": "376",
            "vcardArray": ["vcard", [["fn", {}, "text", "RESERVED-Internet Assigned Numbers Authority"]]],
            "entities": [
                {"roles": ["abuse"],
                 "vcardArray": ["vcard", [["email", {}, "text", "abuse@example.net"]]]}
            ],
        },
        {
            "roles": ["registrant"],
            "vcardArray": ["vcard", [["org", {}, "text", "Example Org"], ["adr", {}, "text", "123 Main St\nPhoenix AZ 85001\nUS"]]],
        },
    ],
}


def test_whois_parses_rdap_payload(tmp_path, monkeypatch):
    ctx, state, out = make_ctx(tmp_path)
    module = WhoisModule(ctx)
    monkeypatch.setattr(module, "_rdap_url", lambda d: "https://rdap.example/domain/example.com")
    ctx.http = FakeHttp({
        "rdap.example": Response(url="u", status=200, body=json.dumps(RDAP_PAYLOAD),
                                 headers={"content-type": "application/rdap+json"}),
    })

    record = module.lookup("example.com")

    assert record["error"] == ""
    assert record["handle"] == "2336799_DOMAIN_COM-VRSN"
    assert record["nameservers"] == ["a.iana-servers.net", "b.iana-servers.net"]
    assert record["events"]["registration"].startswith("1995-08-14")
    assert record["dnssec_signed"] is False
    assert "Reserved" in record["registrar"] or record["registrar"]
    assert record["abuse_email"] == "abuse@example.net"
    assert record["registrant_org"] == "Example Org"


def test_whois_writes_files(tmp_path, monkeypatch):
    ctx, state, out = make_ctx(tmp_path)
    module = WhoisModule(ctx)
    monkeypatch.setattr(module, "_rdap_url", lambda d: "https://rdap.example/x")
    ctx.http = FakeHttp({"rdap.example": Response(url="u", status=200, body=json.dumps(RDAP_PAYLOAD))})
    module.run()

    base = out.dir("whois")
    assert (base / "whois.txt").is_file()
    # The module normalises nameservers to lowercase.
    assert "a.iana-servers.net" in (base / "whois.txt").read_text(encoding="utf-8")
    assert (base / "nameservers.txt").is_file()
    assert (base / "contacts.txt").is_file()
    assert state.whois["nameservers"]


def test_whois_handles_http_error(tmp_path, monkeypatch):
    ctx, state, out = make_ctx(tmp_path)
    module = WhoisModule(ctx)
    monkeypatch.setattr(module, "_rdap_url", lambda d: "https://rdap.example/x")
    ctx.http = FakeHttp({"rdap.example": Response(url="u", status=404, body="")})
    result = module.run()
    assert result["error"] is True
    assert state.whois["error"]
    assert "ERROR" in (out.dir("whois") / "whois.txt").read_text(encoding="utf-8")


def test_whois_unknown_tld(tmp_path):
    ctx, _, _ = make_ctx(tmp_path)
    module = WhoisModule(ctx)
    module._bootstrap = {}
    assert module._rdap_url("thing.invalidtld") is None


# ---------------------------------------------------------------------------
# ASN
# ---------------------------------------------------------------------------


RIPE_RESPONSE = {
    "data": {
        "asns": [{"asn": 13335, "holder": "CLOUDFLARENET - Cloudflare, Inc."}],
        "related_prefixes": [{"resource": "93.184.216.0/24"}],
        "block": {"resource": "93.0.0.0/8"},
    }
}


def test_asn_lookup_parses_ripe(tmp_path):
    ctx, _, _ = make_ctx(tmp_path)
    module = AsnModule(ctx)
    ctx.http = FakeHttp({
        "prefix-overview": Response(url="u", status=200, body=json.dumps(RIPE_RESPONSE)),
    })
    info = module.lookup_ip("93.184.216.34")
    assert info["asn"] == 13335
    assert "Cloudflare" in info["holder"]
    assert info["prefix"] == "93.184.216.0/24"


def test_asn_run_maps_hosts(tmp_path):
    ctx, state, out = make_ctx(tmp_path)
    module = AsnModule(ctx)
    state.dns = {"example.com": {"A": ["93.184.216.34"]}}
    ctx.http = FakeHttp({
        "prefix-overview": Response(url="u", status=200, body=json.dumps(RIPE_RESPONSE)),
        "announced-prefixes": Response(url="u", status=200, body=json.dumps(
            {"data": {"prefixes": [{"prefix": "93.184.216.0/24"}]}})),
    })
    result = module.run()

    assert result["asns"] == 1
    assert "13335" in state.asns
    base = out.dir("asn")
    assert (base / "asn_info.txt").is_file()
    assert "AS13335" in (base / "asn_info.txt").read_text(encoding="utf-8")
    assert (base / "announced_prefixes.txt").is_file()


def test_asn_skips_private_addresses(tmp_path):
    ctx, state, _ = make_ctx(tmp_path)
    module = AsnModule(ctx)
    state.dns = {"internal.example.com": {"A": ["192.168.1.5"]}}
    mapping = module._collect_addresses()
    assert "internal.example.com" not in mapping


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------


def test_header_rules_are_complete():
    for header, rule in HEADER_RULES.items():
        assert rule["severity"] in ("info", "low", "medium", "high")
        assert rule["rationale"]
        assert rule["fix"]
        assert header == header.lower()


def test_headers_module_scores_and_flags(tmp_path):
    ctx, state, out = make_ctx(tmp_path)
    module = HeadersModule(ctx)
    state.live = [{"host": "example.com", "url": "https://example.com/",
                   "final_url": "https://example.com/", "scheme": "https"}]
    ctx.http = FakeHttp({
        "example.com": Response(
            url="u", status=200, body="",
            headers={
                "content-type": "text/html",
                "x-content-type-options": "nosniff",
                "content-security-policy": "script-src 'self' 'unsafe-inline'",
                "strict-transport-security": "max-age=0",
                "server": "nginx/1.24.0",
            },
        ),
    })
    module.run()

    assert len(state.header_audits) == 1
    audit = state.header_audits[0]
    assert audit["score"] < audit["max_score"]
    # HSTS present but max-age=0 is a weakness.
    assert any("max-age is 0" in w for w in audit["weaknesses"])
    assert any("unsafe-inline" in w for w in audit["weaknesses"])
    assert "server" in audit["disclosures"]

    base = out.dir("headers")
    assert (base / "security_headers.txt").is_file()
    assert (base / "security_headers.json").is_file()
    assert (base / "missing_by_frequency.txt").is_file()


def test_headers_module_handles_no_live_hosts(tmp_path):
    ctx, _, _ = make_ctx(tmp_path)
    assert HeadersModule(ctx).run()["hosts"] == 0


# ---------------------------------------------------------------------------
# WAF
# ---------------------------------------------------------------------------


def test_waf_signatures_present():
    names = {sig[0] for sig in SIGNATURES}
    for expected in ("Cloudflare", "Akamai", "AWS WAF / CloudFront", "Sucuri"):
        assert expected in names


def test_waf_detects_cloudflare_from_headers(tmp_path):
    ctx, state, out = make_ctx(tmp_path)
    module = WafModule(ctx)
    state.live = [{"host": "example.com", "url": "https://example.com/",
                   "final_url": "https://example.com/", "scheme": "https"}]
    ctx.http = FakeHttp({
        "example.com": Response(
            url="u", status=200, body="<html>ok</html>",
            headers={"cf-ray": "8abc123", "server": "cloudflare"},
        ),
    })
    module.run()
    assert state.waf_results
    assert state.waf_results[0]["waf_detected"] is True
    assert "Cloudflare" in state.waf_results[0]["signatures"]
    assert "DETECTED" in (out.dir("waf") / "waf_results.txt").read_text(encoding="utf-8")


def test_waf_detects_behavioural_blocking(tmp_path):
    ctx, state, _ = make_ctx(tmp_path)
    module = WafModule(ctx)
    state.live = [{"host": "example.com", "url": "https://example.com/",
                   "final_url": "https://example.com/", "scheme": "https"}]
    big = "<html>" + "x" * 5000 + "</html>"

    def responder(url, **kwargs):
        if "q=" in url:
            return Response(url=url, status=403, body="blocked",
                            headers={"content-type": "text/html"})
        return Response(url=url, status=200, body=big,
                        headers={"content-type": "text/html"})

    ctx.http.get = responder
    module.run()
    entry = state.waf_results[0]
    assert entry["blocked_probes"] >= 2
    assert entry["waf_detected"] is True


def test_waf_no_false_positive_on_plain_site(tmp_path):
    # The host must be in scope for _bases() to include it.
    ctx, state, _ = make_ctx(tmp_path, domain="plain.test")
    module = WafModule(ctx)
    state.live = [{"host": "plain.test", "url": "https://plain.test/",
                   "final_url": "https://plain.test/", "scheme": "https"}]
    ctx.http.get = lambda url, **k: Response(
        url=url, status=200, body="<html>hello</html>",
        headers={"content-type": "text/html", "server": "nginx"},
    )
    module.run()
    # nginx is a known server signature in our table; it must not read as a WAF.
    entry = state.waf_results[0]
    assert entry["blocked_probes"] == 0


def test_block_statuses_are_sane():
    for status in (403, 406, 429):
        assert status in BLOCK_STATUSES
    assert 200 not in BLOCK_STATUSES
    assert len(PROBES) >= 3


# ---------------------------------------------------------------------------
# WordPress
# ---------------------------------------------------------------------------


def test_wordpress_regexes():
    html = '<link href="/wp-content/plugins/contact-form-7/includes/css/x.css">'
    assert PLUGIN_RE.findall(html) == ["contact-form-7"]
    theme = '<script src="/wp-content/themes/twentytwentyfour/app.js"></script>'
    assert THEME_RE.findall(theme) == ["twentytwentyfour"]


def test_wordpress_version_patterns():
    body = '<meta name="generator" content="WordPress 6.4.3">'
    assert any(p.search(body) for p in VERSION_PATTERNS)
    found = VERSION_PATTERNS[0].search(body)
    assert found.group(1) == "6.4.3"


def test_wordpress_detects_and_enumerates(tmp_path):
    ctx, state, out = make_ctx(tmp_path)
    page = (
        '<html><head><meta name="generator" content="WordPress 6.4.3">'
        '<link href="/wp-content/plugins/akismet/x.css">'
        '<link href="/wp-content/themes/twentytwentyfour/y.css">'
        '</head><body class="wp-emoji"></body></html>'
    )
    routes = {
        "readme.html": Response(url="u", status=200, body="<h1>WordPress</h1>"),
        "xmlrpc.php": Response(url="u", status=405, body="XML-RPC only"),
        "wp/v2/users": Response(url="u", status=200,
                                body='[{"id":1,"name":"Admin","slug":"admin"}]'),
        "author=1": Response(url="u", status=301, body="",
                             headers={"location": "https://example.com/author/editor"}),
    }
    ctx.http = FakeHttp({**routes, "example.com": html_response("https://example.com/", page)})
    ctx.http = {"example.com": html_response("https://example.com/", page)}
    state.live = [{"host": "example.com", "url": "https://example.com/",
                   "final_url": "https://example.com/", "scheme": "https"}]

    from .test_modules import FakeHttp as FH

    class Routed(FH):
        def get(self, url, **kwargs):
            for pattern, resp in routes.items():
                if pattern in url:
                    return resp
            if url.rstrip("/") == "https://example.com":
                return html_response(url, page)
            return Response(url=url, status=404, body="")

    ctx.http = Routed({})

    module = WordPressModule(ctx)
    module.run()

    assert state.wordpress_sites, "WordPress should have been detected"
    site = state.wordpress_sites[0]
    assert site["version"] == "6.4.3"
    assert "akismet" in site["plugins"]
    assert "twentytwentyfour" in site["themes"]
    assert "admin" in site["users"]
    base = out.dir("wordpress")
    assert (base / "wordpress.txt").is_file()
    assert (base / "plugins.txt").is_file()
    assert "akismet" in (base / "plugins.txt").read_text(encoding="utf-8")


def test_wordpress_ignores_non_wordpress(tmp_path):
    ctx, state, _ = make_ctx(tmp_path)
    state.live = [{"host": "example.com", "url": "https://example.com/",
                   "final_url": "https://example.com/", "scheme": "https"}]
    ctx.http = FakeHttp({"example.com": html_response("https://example.com/",
                                                     "<html><body>plain site</body></html>")})
    WordPressModule(ctx).run()
    assert state.wordpress_sites == []
