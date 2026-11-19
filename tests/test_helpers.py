"""Tests for shared helpers, de-duplication and HTTP parsing utilities."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from fullrecon.core.deduplication import Counter, Deduplicator, dedupe_lines, unique_pairs
from fullrecon.core.scanner import _decode, _dechunk, _read_response, RateLimiter
from fullrecon.utils.helpers import (
    absolute_url,
    chunked,
    dedupe,
    extract_html_info,
    extract_title,
    extract_urls,
    format_table,
    is_interesting,
    load_wordlist,
    normalise_url,
    query_params,
    read_lines,
    safe_filename,
    truncate,
    url_host,
    url_without_query,
    write_lines,
)


class TestFiles:
    def test_write_and_read_roundtrip(self, tmp_path):
        path = tmp_path / "sub" / "out.txt"
        count = write_lines(path, ["a", "b", "", "  c  "])
        assert count == 3
        assert read_lines(path) == ["a", "b", "c"]

    def test_read_missing_file_returns_empty(self, tmp_path):
        assert read_lines(tmp_path / "nope.txt") == []

    def test_write_lines_strips_newlines(self, tmp_path):
        path = tmp_path / "x.txt"
        write_lines(path, ["line1\nline2"])
        assert read_lines(path) == ["line1 line2"]

    def test_load_wordlist_skips_comments(self, tmp_path):
        path = tmp_path / "w.txt"
        path.write_text("admin\n# comment\n\napi\nadmin\n", encoding="utf-8")
        assert load_wordlist(path) == ["admin", "api"]


class TestCollections:
    def test_dedupe_preserves_order(self):
        assert dedupe(["b", "a", "b", "c", "a"]) == ["b", "a", "c"]

    def test_dedupe_skips_empty(self):
        assert dedupe(["a", "", None, "  "]) == ["a"]

    def test_chunked(self):
        assert [list(c) for c in chunked([1, 2, 3, 4, 5], 2)] == [[1, 2], [3, 4], [5]]

    def test_deduplicator_thread_safety(self):
        dedup = Deduplicator(lowercase=True)

        def worker(prefix):
            for i in range(300):
                dedup.add(f"{prefix}{i}")

        threads = [threading.Thread(target=worker, args=(p,)) for p in "abc"]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(dedup) == 900  # 3 prefixes x 300 distinct values
        dedup.add("A0")
        assert "a0" in dedup

    def test_unique_pairs(self):
        pairs = [("a", "b"), ("a", "b"), ("c", "d"), ("", "x")]
        assert unique_pairs(pairs) == [("a", "b"), ("c", "d")]

    def test_counter(self):
        counter = Counter()
        counter.incr("x")
        counter.incr("x", 2)
        assert counter.get("x") == 3
        assert counter.get("missing", 0) == 0
        assert counter.as_dict() == {"x": 3}

    def test_dedupe_lines(self):
        assert dedupe_lines(["A", "a", "b"], lowercase=True) == ["a", "b"]


class TestUrls:
    def test_normalise_url_sorts_query_and_lowercases_host(self):
        assert normalise_url("HTTPS://ExAmple.COM:443/a?z=1&a=2#frag") == "https://example.com/a?a=2&z=1"

    def test_normalise_keeps_non_default_port(self):
        assert normalise_url("http://example.com:8080/x") == "http://example.com:8080/x"

    def test_url_without_query(self):
        assert url_without_query("https://example.com/a?b=1") == "https://example.com/a"

    def test_absolute_url(self):
        assert absolute_url("https://example.com/a/b", "../c") == "https://example.com/c"
        assert absolute_url("https://example.com/", "//cdn.example.com/x.js") == "https://cdn.example.com/x.js"
        assert absolute_url("https://example.com/", "mailto:a@b.c") is None
        assert absolute_url("https://example.com/", "javascript:void(0)") is None

    def test_extract_urls(self):
        text = "see https://a.com/x, and http://b.com/y). plus https://a.com/x"
        assert extract_urls(text) == ["https://a.com/x", "http://b.com/y"]

    def test_query_params(self):
        assert query_params("https://a.com/?b=1&a=2") == ["b", "a"]
        assert query_params("https://a.com/path") == []


class TestHtml:
    def test_extract_title(self):
        assert extract_title("<html><title>  Hello\n World </title>") == "Hello World"
        assert extract_title("<html>no title</html>") == ""

    def test_extract_html_info(self):
        html = """
        <html><head>
          <base href="https://example.com/app/">
          <meta name="generator" content="WordPress 6.4">
          <script src="js/main.js"></script>
          <link href="/static/site.css" rel="stylesheet">
        </head><body>
          <a href="page2">two</a>
          <form action="/login"></form>
          <!-- TODO: remove debug endpoint /internal/debug -->
        </body></html>
        """
        info = extract_html_info(html, "https://example.com/")
        assert "https://example.com/app/js/main.js" in info["scripts"]
        assert "https://example.com/static/site.css" in info["links"]
        assert "https://example.com/app/page2" in info["hrefs"]
        # "/login" is root-relative, so <base> does not apply (browser behaviour).
        assert "https://example.com/login" in info["forms"]
        assert any("TODO" in c for c in info["comments"])
        assert info["generators"] == ["WordPress 6.4"]

    def test_is_interesting(self):
        assert is_interesting("https://a.com/admin/login")
        assert is_interesting("https://a.com/.env")
        assert not is_interesting("https://a.com/about-us")


class TestMisc:
    def test_safe_filename(self):
        assert safe_filename("a/b c?d") == "a_b_c_d"
        assert safe_filename("") == "item"
        assert len(safe_filename("x" * 200)) == 80

    def test_truncate(self):
        assert truncate("short", 20) == "short"
        assert truncate("x" * 50, 10) == "xxxxxxx..."

    def test_format_table(self):
        assert "label" in format_table([("label", "value")])


class TestHttpParsing:
    def test_decode_gzip_and_charset(self):
        import gzip

        raw = gzip.compress("héllo".encode("utf-8"))
        assert _decode(raw, {"content-encoding": "gzip", "content-type": "text/html; charset=utf-8"}) == "héllo"

    def test_decode_latin1(self):
        assert _decode("café".encode("latin-1"), {"content-type": "text/plain; charset=latin-1"}) == "café"

    def test_read_response_simple(self):
        class FakeConn:
            def __init__(self, payload):
                self.payload = payload

            def recv(self, n):
                data, self.payload = self.payload[:n], self.payload[n:]
                return data

        payload = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Test: 1\r\n\r\nhello"
        status, headers, body = _read_response(FakeConn(payload), True, 1024)
        assert status == 200
        assert headers["x-test"] == "1"
        assert body == b"hello"

    def test_read_response_rejects_garbage(self):
        class FakeConn:
            def recv(self, n):
                return b"NOT HTTP\r\n\r\n"

        with pytest.raises(ConnectionError):
            _read_response(FakeConn(), True, 1024)

    def test_rate_limiter_no_rate_is_noop(self):
        limiter = RateLimiter(0)
        limiter.wait("example.com")  # must return instantly
