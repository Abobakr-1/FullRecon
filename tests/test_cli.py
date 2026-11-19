"""CLI, config and end-to-end pipeline tests (no external network)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from fullrecon.cli import (
    build_config,
    build_parser,
    main,
    parse_ports,
    selected_modules,
    top_ports,
)
from fullrecon.config import Config, merge
from fullrecon.core.orchestrator import ALL_MODULES, MODULE_GROUPS, PIPELINE, Orchestrator
from fullrecon.core.output_manager import OutputExists, OutputManager
from fullrecon.utils.validators import ValidationError


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def test_help_and_version_exit_cleanly(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "usage:" in out.lower()
    assert "--domain" in out

    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0


def test_requires_a_target(capsys):
    assert main([]) == 2
    assert "target is required" in capsys.readouterr().err


def test_invalid_target_is_rejected(capsys):
    assert main(["-d", "not a domain!", "--authorized"]) == 2
    assert "error:" in capsys.readouterr().err


def test_list_modules(capsys):
    assert main(["--list-modules"]) == 0
    out = capsys.readouterr().out
    for name in ALL_MODULES:
        assert name in out


def test_parse_ports_variants():
    assert parse_ports("80,443") == [80, 443]
    assert parse_ports("8000-8003") == [8000, 8001, 8002, 8003]
    assert parse_ports(" 80 , 80 ,8080 ") == [80, 8080]
    assert parse_ports(None) == []
    assert parse_ports("") == []
    with pytest.raises(ValidationError):
        parse_ports("abc")
    with pytest.raises(ValidationError):
        parse_ports("80-abc")


def test_top_ports():
    ports = top_ports(5)
    assert len(ports) == 5
    assert ports[0] == 80
    assert 443 in ports


@pytest.mark.parametrize("argv,expected", [
    (["--full"], set(MODULE_GROUPS["full"])),
    (["--passive"], set(MODULE_GROUPS["passive"])),
    (["--subdomains"], {"subdomains"}),
    (["--api"], {"subdomains", "dns", "api"}),
    (["--js"], {"subdomains", "dns", "javascript"}),
    ([], None),
])
def test_selected_modules(argv, expected):
    args = build_parser().parse_args(["-d", "example.com"] + argv)
    result = selected_modules(args)
    assert (set(result) if result else None) == expected


def test_every_pipeline_key_is_known():
    assert set(ALL_MODULES) == {key for key, *_ in PIPELINE}
    for group, modules in MODULE_GROUPS.items():
        assert set(modules) <= set(ALL_MODULES), f"group {group} has unknown module"


# ---------------------------------------------------------------------------
# Config assembly
# ---------------------------------------------------------------------------


def test_build_config_applies_flags():
    args = build_parser().parse_args([
        "-d", "https://Example.com/path",
        "--threads", "7", "--rate-limit", "3.5", "--timeout", "4",
        "--ports-list", "80,443", "--no-nmap", "--no-resolve",
        "--in-scope", "partner.net", "--out-of-scope", "dev.example.com",
        "--allowed-ports", "443",
        "--no-color",
    ])
    cfg = build_config(args)
    assert cfg.domain == "example.com"
    assert cfg.threads == 7
    assert cfg.rate_limit == 3.5
    assert cfg.timeout == 4.0
    assert cfg.ports == [80, 443]
    assert cfg.use_nmap is False
    assert cfg.resolve_subdomains is False
    assert cfg.scope["in_scope"] == ["partner.net"]
    assert cfg.scope["out_of_scope"] == ["dev.example.com"]
    assert cfg.scope["allowed_ports"] == [443]


def test_build_config_rejects_bad_threads():
    args = build_parser().parse_args(["-d", "example.com", "--threads", "0"])
    with pytest.raises(ValidationError):
        build_config(args)


def test_build_config_reads_json_file(tmp_path):
    path = tmp_path / "cfg.json"
    path.write_text(json.dumps({"threads": 3, "rate_limit": 1.0}), encoding="utf-8")
    args = build_parser().parse_args(["-d", "example.com", "--config", str(path)])
    cfg = build_config(args)
    assert cfg.threads == 3
    assert cfg.rate_limit == 1.0


def test_build_config_missing_file(tmp_path):
    args = build_parser().parse_args(["-d", "example.com", "--config", str(tmp_path / "nope.json")])
    with pytest.raises(ValidationError):
        build_config(args)


def test_config_merge_keeps_defaults():
    base = Config()
    override = Config(threads=5)
    merged = merge(base, override)
    assert merged.threads == 5
    assert merged.rate_limit == base.rate_limit
    assert merged.ports == base.ports


def test_config_roundtrip():
    cfg = Config(domain="example.com", threads=9)
    restored = Config.from_dict(cfg.to_dict())
    assert restored.threads == 9
    assert restored.domain == "example.com"


# ---------------------------------------------------------------------------
# Output manager
# ---------------------------------------------------------------------------


def test_output_manager_creates_tree(tmp_path):
    cfg = Config(domain="example.com", out_dir=str(tmp_path))
    manager = OutputManager(cfg)
    manager.prepare()
    from fullrecon.config import OUTPUT_DIRS
    for folder in (OUTPUT_DIRS["subdomains"], OUTPUT_DIRS["dns"],
                   OUTPUT_DIRS["reports"], OUTPUT_DIRS["logs"], OUTPUT_DIRS["raw"]):
        assert (manager.target_dir / folder).is_dir()
    assert (manager.target_dir / "README.txt").is_file()


def test_output_manager_refuses_silent_overwrite(tmp_path):
    cfg = Config(domain="example.com", out_dir=str(tmp_path))
    OutputManager(cfg).prepare().joinpath("keep.txt").write_text("x", encoding="utf-8")
    with pytest.raises(OutputExists):
        OutputManager(cfg).prepare()


def test_output_manager_overwrite_flag(tmp_path):
    cfg = Config(domain="example.com", out_dir=str(tmp_path))
    first = OutputManager(cfg).prepare()
    (first / "stale.txt").write_text("old", encoding="utf-8")
    cfg.overwrite = True
    second = OutputManager(cfg).prepare()
    assert not (second / "stale.txt").exists()


def test_output_manager_timestamped(tmp_path):
    cfg = Config(domain="example.com", out_dir=str(tmp_path), timestamped=True)
    manager = OutputManager(cfg)
    manager.prepare()
    assert manager.target_dir.parent == (tmp_path / "example.com").resolve()
    assert len(manager.target_dir.name) == 15  # YYYYmmdd-HHMMSS


def test_output_writers_and_manifest(tmp_path):
    cfg = Config(domain="example.com", out_dir=str(tmp_path))
    manager = OutputManager(cfg)
    manager.prepare()
    assert manager.write("subdomains", "x.txt", ["a", "b", "a"]) == 3
    manager.write_json("dns", "d.json", {"k": "v"})
    manifest = manager.write_manifest()
    data = json.loads(manifest.read_text(encoding="utf-8"))
    assert data["target"] == "example.com"
    assert any(f["path"].endswith("01-Subdomains/x.txt") for f in data["files"])
    assert "01-Subdomains/" in manager.tree_text()


# ---------------------------------------------------------------------------
# Orchestrator end-to-end (all modules stubbed)
# ---------------------------------------------------------------------------


ALL_MODULE_RUN_PATHS = (
    "fullrecon.modules.subdomains.SubdomainModule.run",
    "fullrecon.modules.dns.DnsModule.run",
    "fullrecon.modules.whois.WhoisModule.run",
    "fullrecon.modules.asn.AsnModule.run",
    "fullrecon.modules.portscan.PortScanModule.run",
    "fullrecon.modules.live_hosts.LiveHostModule.run",
    "fullrecon.modules.technologies.TechnologyModule.run",
    "fullrecon.modules.headers.HeadersModule.run",
    "fullrecon.modules.waf.WafModule.run",
    "fullrecon.modules.urls.UrlModule.run",
    "fullrecon.modules.javascript.JavaScriptModule.run",
    "fullrecon.modules.api.ApiModule.run",
    "fullrecon.modules.content_discovery.ContentModule.run",
    "fullrecon.modules.wordpress.WordPressModule.run",
    "fullrecon.modules.intelligence.IntelligenceModule.run",
)


class _NoNetworkHttp:
    requests = 0

    def get(self, url, **kwargs):
        from fullrecon.core.scanner import Response

        _NoNetworkHttp.requests += 1
        return Response(url=url, status=404, body="", headers={})


def test_orchestrator_runs_pipeline_and_writes_reports(tmp_path, monkeypatch):
    cfg = Config(domain="example.com", out_dir=str(tmp_path), threads=2, rate_limit=0)
    cfg.resolved()
    orchestrator = Orchestrator(cfg)
    orchestrator.prepare()

    # Replace the HTTP client so nothing touches the network.
    orchestrator.http = _NoNetworkHttp()
    orchestrator.ctx.http = orchestrator.http

    import fullrecon.modules.subdomains as sub
    monkeypatch.setattr(sub.SubdomainModule, "run", lambda self: {"unique": 3})
    monkeypatch.setattr(
        "fullrecon.modules.dns.DnsModule.run", lambda self: {"hosts": 1},
    )
    for module_path in ALL_MODULE_RUN_PATHS:
        monkeypatch.setattr(module_path, lambda self: {})

    state = orchestrator.run(MODULE_GROUPS["default"])

    reports = orchestrator.out.dir("reports")
    assert (reports / "summary.txt").is_file()
    assert (reports / "report.json").is_file()
    assert (reports / "report.html").is_file()
    payload = json.loads((reports / "report.json").read_text(encoding="utf-8"))
    assert payload["tool"]["name"] == "FullRecon"
    assert payload["scan"]["target"] == "example.com"
    assert state.started_at and state.finished_at
    assert all(v.get("ok") for v in state.module_status.values()), state.module_status


def test_orchestrator_survives_module_crash(tmp_path, monkeypatch):
    cfg = Config(domain="example.com", out_dir=str(tmp_path), rate_limit=0)
    cfg.resolved()
    orchestrator = Orchestrator(cfg)
    orchestrator.prepare()
    orchestrator.http = _NoNetworkHttp()
    orchestrator.ctx.http = orchestrator.http

    def boom(self):
        raise RuntimeError("module exploded")

    monkeypatch.setattr("fullrecon.modules.subdomains.SubdomainModule.run", boom)
    monkeypatch.setattr("fullrecon.modules.intelligence.IntelligenceModule.run", lambda self: {})

    state = orchestrator.run(["subdomains", "intel"])
    assert state.module_status["subdomains"]["ok"] is False
    assert "module exploded" in state.module_status["subdomains"]["detail"]
    assert state.module_status["intel"]["ok"] is True


def test_passive_mode_skips_active_modules(tmp_path, monkeypatch):
    cfg = Config(domain="example.com", out_dir=str(tmp_path), passive_only=True, rate_limit=0)
    cfg.resolved()
    orchestrator = Orchestrator(cfg)
    orchestrator.prepare()
    for module_path in (
        "fullrecon.modules.subdomains.SubdomainModule.run",
        "fullrecon.modules.dns.DnsModule.run",
        "fullrecon.modules.intelligence.IntelligenceModule.run",
        "fullrecon.modules.live_hosts.LiveHostModule.run",
        "fullrecon.modules.portscan.PortScanModule.run",
    ):
        monkeypatch.setattr(module_path, lambda self: {})
    state = orchestrator.run(["subdomains", "dns", "ports", "live", "intel"])
    assert state.module_status["ports"].get("skipped") is True
    assert state.module_status["live"].get("skipped") is True


def test_cli_authorization_gate(capsys, tmp_path, monkeypatch):
    monkeypatch.delenv("FULLRECON_ACCEPT_AUTHORIZATION", raising=False)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    code = main(["-d", "example.com", "-o", str(tmp_path), "--no-color"])
    assert code == 3
    assert "authorized" in capsys.readouterr().err.lower()


def test_cli_full_run_offline(tmp_path, monkeypatch):
    """Smoke-test the whole CLI with modules stubbed out."""
    for module_path in ALL_MODULE_RUN_PATHS:
        monkeypatch.setattr(module_path, lambda self: {})

    code = main([
        "-d", "example.com", "--authorized", "--yes", "--no-color",
        "-o", str(tmp_path), "--threads", "2", "--rate-limit", "0",
        "--ports-list", "80", "--no-nmap",
    ])
    assert code == 0
    from fullrecon.config import OUTPUT_DIRS
    assert (tmp_path / "example.com" / OUTPUT_DIRS["reports"] / "report.html").is_file()