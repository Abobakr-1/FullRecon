"""Adapter parsing tests using fake binaries.

These exercise the *parsing* half of each adapter — the part that turns real
tool output into ``ToolResult.items`` — without requiring the actual tool. A
stub executable is placed on ``PATH`` ahead of everything else, so
``shutil.which`` resolves it and the adapter runs end to end.

This closes a real coverage gap: nmap, whatweb, wafw00f, wpscan and amass are
not installed on the development machine, so their parsing was previously only
reachable through manual inspection.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from fullrecon.core import tools


def make_stub(bindir: Path, name: str, stdout: str, exit_code: int = 0) -> Path:
    """Create an executable stub named *name* that prints *stdout*."""
    if os.name == "nt":
        # .bat is the simplest executable shim on Windows.
        path = bindir / f"{name}.bat"
        # Escape % for batch, then emit the payload via echo lines.
        body = "@echo off\n"
        for line in stdout.splitlines():
            escaped = line.replace("%", "%%").replace("^", "^^").replace("&", "^&")
            escaped = escaped.replace("<", "^<").replace(">", "^>").replace("|", "^|")
            body += f"echo {escaped}\n"
        body += f"exit /b {exit_code}\n"
        path.write_text(body, encoding="utf-8")
    else:
        path = bindir / name
        path.write_text(f"#!/bin/sh\ncat <<'STUBEOF'\n{stdout}\nSTUBEOF\nexit {exit_code}\n",
                        encoding="utf-8")
    path.chmod(0o755)
    return path


@pytest.fixture
def stub_path(tmp_path, monkeypatch):
    """Prepend a directory of stubs to PATH and clear which()'s cache."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ.get("PATH", ""))
    return bindir


# ---------------------------------------------------------------------------
# nmap
# ---------------------------------------------------------------------------

NMAP_OUTPUT = """Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.087s latency).
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.7 ((Ubuntu))
9929/tcp open  nping-echo Nping echo
Service detection performed.
"""


def test_nmap_adapter_parses_service_lines(stub_path):
    make_stub(stub_path, "nmap", NMAP_OUTPUT)
    result = tools.nmap_services(["scanme.nmap.org"], ports=[22, 80, 9929])

    assert result.ok is True
    assert result.available is True
    assert len(result.items) == 3
    assert any("/tcp" in line and "ssh" in line for line in result.items)
    assert any("Apache" in line for line in result.items)


def test_nmap_adapter_reports_nonzero_exit(stub_path):
    make_stub(stub_path, "nmap", "", exit_code=1)
    result = tools.nmap_services(["example.com"])
    assert result.ok is False
    assert result.available is True
    assert result.error


# ---------------------------------------------------------------------------
# whatweb
# ---------------------------------------------------------------------------

WHATWEB_JSON = '{"target":"https://example.com","plugins":{"Apache":{"version":["2.4.7"]},"PHP":{"version":["8.1"]}}}'


def test_whatweb_adapter_reads_json_log(stub_path, tmp_path):
    """The stub honours --log-json, so the adapter's real parsing path runs."""
    impl = tmp_path / "whatweb_impl.py"
    impl.write_text(
        "import sys, pathlib\n"
        "args = sys.argv[1:]\n"
        "out = args[args.index('--log-json') + 1]\n"
        f"pathlib.Path(out).write_text({WHATWEB_JSON!r}, encoding='utf-8')\n",
        encoding="utf-8",
    )

    if os.name == "nt":
        stub = stub_path / "whatweb.bat"
        stub.write_text(
            f'@echo off\n"{sys.executable}" "{impl}" %*\nexit /b %ERRORLEVEL%\n',
            encoding="utf-8",
        )
    else:
        stub = stub_path / "whatweb"
        stub.write_text(
            f'#!/bin/sh\nexec "{sys.executable}" "{impl}" "$@"\n',
            encoding="utf-8",
        )
    stub.chmod(0o755)

    result = tools.whatweb(["https://example.com"])

    assert result.ok is True
    assert len(result.items) == 1
    # The adapter must return the JSON line it read back from the log file.
    assert '"Apache"' in result.items[0]
    assert "2.4.7" in result.items[0]


# ---------------------------------------------------------------------------
# wafw00f
# ---------------------------------------------------------------------------

WAFW00F_OUTPUT = """[*] Checking https://example.com
[+] The site https://example.com is behind Cloudflare (Cloudflare Inc.) WAF.
{"firewall": "Cloudflare", "manufacturer": "Cloudflare Inc."}
{"firewall": "None", "manufacturer": "None"}
"""


def test_wafw00f_adapter_extracts_firewall_names(stub_path):
    make_stub(stub_path, "wafw00f", WAFW00F_OUTPUT)
    result = tools.wafw00f("https://example.com")

    assert result.ok is True
    assert "Cloudflare" in result.items
    # "None" must not be reported as a detected WAF.
    assert "None" not in result.items


# ---------------------------------------------------------------------------
# wpscan
# ---------------------------------------------------------------------------

WPSCAN_OUTPUT = '{"version":{"number":"6.4.3"},"plugins":{"akismet":{"version":"5.0"}},"users":{"admin":{}}}'


def test_wpscan_adapter_returns_raw_json(stub_path):
    make_stub(stub_path, "wpscan", WPSCAN_OUTPUT)
    result = tools.wpscan("https://blog.example.com")

    assert result.ok is True
    assert len(result.items) == 1
    assert '"number":"6.4.3"' in result.items[0]


# ---------------------------------------------------------------------------
# amass
# ---------------------------------------------------------------------------

AMASS_ORG_OUTPUT = """example.com
example.net
not-a-domain
third-example.org
"""


def test_amass_org_adapter_filters_non_domains(stub_path):
    make_stub(stub_path, "amass", AMASS_ORG_OUTPUT)
    result = tools.amass_intel_org("Example Inc")

    assert result.ok is True
    assert "example.com" in result.items
    assert "example.net" in result.items
    assert "not-a-domain" not in result.items


# ---------------------------------------------------------------------------
# subfinder / assetfinder / katana parsing (binaries present in dev env)
# ---------------------------------------------------------------------------

SUBFINDER_OUTPUT = """www.example.com
api.example.com
WWW.Example.COM
example.com
"""


def test_subfinder_adapter_normalises_case(stub_path):
    make_stub(stub_path, "subfinder", SUBFINDER_OUTPUT)
    result = tools.subfinder("example.com", all_sources=False)

    assert result.ok is True
    assert "www.example.com" in result.items
    assert "api.example.com" in result.items
    # Deduplication happens downstream; the adapter lowercases.
    assert all(name == name.lower() for name in result.items)


KATANA_OUTPUT = """https://example.com/
https://example.com/login
not a url
https://example.com/api/v1/users
"""


def test_katana_adapter_keeps_only_urls(stub_path):
    make_stub(stub_path, "katana", KATANA_OUTPUT)
    result = tools.katana("https://example.com", depth=2)

    assert result.ok is True
    assert "https://example.com/login" in result.items
    assert "not a url" not in result.items
    assert len(result.items) == 3


def test_adapter_timeout_is_reported(stub_path):
    """A stub that sleeps past the timeout must produce a clean failure."""
    script = stub_path / "sleepy.bat" if os.name == "nt" else stub_path / "sleepy"
    if os.name == "nt":
        script.write_text("@echo off\nping -n 6 127.0.0.1 >nul\nexit /b 0\n", encoding="utf-8")
    else:
        script.write_text("#!/bin/sh\nsleep 6\necho late\n", encoding="utf-8")
    script.chmod(0o755)

    result = tools.run_tool("sleepy", [], timeout=1.0)
    assert result.ok is False
    assert "timed out" in result.error.lower()
