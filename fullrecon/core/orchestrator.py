"""Pipeline orchestration: runs modules in order and chains their outputs."""

from __future__ import annotations

import sys
import threading
import time
import traceback
from typing import Callable, Dict, List, Optional, Type

from ..config import Config
from ..utils.colors import Colors
from ..utils.logger import Logger, get_logger
from ..utils.progress import ProgressBar, human_duration
from .context import ModuleContext, ReconState
from .output_manager import OutputExists, OutputManager
from .report_generator import ReportGenerator
from .scanner import HttpClient
from .scope import Scope

from ..modules.api import ApiModule
from ..modules.content_discovery import ContentModule
from ..modules.dns import DnsModule
from ..modules.intelligence import IntelligenceModule
from ..modules.javascript import JavaScriptModule
from ..modules.live_hosts import LiveHostModule
from ..modules.portscan import PortScanModule
from ..modules.subdomains import SubdomainModule
from ..modules.technologies import TechnologyModule
from ..modules.urls import UrlModule


# (key, module class, allowed in --passive mode, sends traffic to the target)
# "Passive" means: only reads third-party datasets and public DNS.  Anything
# that opens a connection to the target itself is excluded.
PIPELINE: List[tuple] = [
    ("subdomains", SubdomainModule, True, False),
    ("dns", DnsModule, True, True),
    ("ports", PortScanModule, False, True),
    ("live", LiveHostModule, False, True),
    ("technologies", TechnologyModule, False, True),
    ("urls", UrlModule, False, True),
    ("javascript", JavaScriptModule, False, True),
    ("api", ApiModule, False, True),
    ("content", ContentModule, False, True),
    ("intel", IntelligenceModule, True, False),
]

ALL_MODULES = [key for key, *_ in PIPELINE]

# Convenience groupings used by the CLI flags.
MODULE_GROUPS = {
    "full": ALL_MODULES,
    "default": ["subdomains", "dns", "ports", "live", "technologies", "urls", "javascript", "api", "content", "intel"],
    "passive": ["subdomains", "dns", "intel"],
    "active": ["ports", "live", "technologies", "urls", "javascript", "api", "content", "intel"],
    "subdomains": ["subdomains"],
    "ports": ["ports"],
    "api": ["api"],
    "js": ["javascript"],
}


class Orchestrator:
    """Owns the scan lifecycle: setup, module sequencing, reporting."""

    def __init__(self, cfg: Config, logger: Optional[Logger] = None) -> None:
        self.cfg = cfg
        self.log = logger or get_logger("orchestrator")
        self.state = ReconState(target=cfg.domain)
        cfg.resolved()
        self.scope = Scope(
            cfg.domain,
            in_scope=cfg.scope.get("in_scope") or [],
            out_of_scope=cfg.scope.get("out_of_scope") or [],
            allowed_ports=cfg.scope.get("allowed_ports") or [],
            scope_file=cfg.scope.get("file"),
        )
        self.http = HttpClient(cfg, self.scope, self.log)
        self.out = OutputManager(cfg, self.log)
        self.ctx: Optional[ModuleContext] = None
        self.report_paths: Dict[str, str] = {}
        self._stop = threading.Event()

    # ------------------------------------------------------------------
    def stop(self) -> None:
        self._stop.set()

    def prepare(self, confirm: Optional[Callable] = None) -> None:
        self.out.prepare(confirm=confirm)
        self.ctx = ModuleContext(
            cfg=self.cfg,
            scope=self.scope,
            http=self.http,
            out=self.out,
            state=self.state,
            logger=self.log,
            passive=self.cfg.passive_only,
        )
        Logger.attach_file(self.out.log_path())
        self.log.debug("scope: %s", self.scope.describe().replace("\n", " | "))

    # ------------------------------------------------------------------
    def run(self, modules: Optional[List[str]] = None) -> ReconState:
        if self.ctx is None:
            self.prepare()

        selected = modules or MODULE_GROUPS["default"]
        selected = [m for m in ALL_MODULES if m in set(selected)]
        if not selected:
            raise ValueError("no modules selected")

        self.state.started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        started = time.time()

        self._print_banner(selected)
        total = len(selected)
        for index, key in enumerate(selected, start=1):
            if self._stop.is_set():
                self.log.warning("scan interrupted by user")
                break
            entry = next((e for e in PIPELINE if e[0] == key), None)
            if entry is None:
                continue
            _, module_cls, passive_safe, needs_target = entry

            if self.cfg.passive_only and not passive_safe:
                self.state.module_status[key] = {
                    "ok": False, "skipped": True, "duration": 0.0,
                    "detail": "skipped (passive-only mode)",
                }
                self.log.info("[%d/%d] %s - skipped in passive mode", index, total, module_cls.label)
                continue

            self._print_module_header(index, total, module_cls.label)
            status = {"ok": False, "skipped": False, "duration": 0.0, "detail": ""}
            start = time.time()
            try:
                module = module_cls(self.ctx)
                result = module.run() or {}
                status["ok"] = True
                status["duration"] = time.time() - start
                status["detail"] = ", ".join(f"{k}={v}" for k, v in result.items() if not isinstance(v, dict))
            except Exception as exc:  # noqa: BLE001 - a module crash must not kill the run
                status["duration"] = time.time() - start
                status["detail"] = f"{type(exc).__name__}: {exc}"
                self.state.errors.append(f"{key}: {exc}")
                self.log.error("%s failed: %s", module_cls.label, exc)
                if not getattr(self, "_debug", False):
                    self.log.debug(traceback.format_exc())
            self.state.module_status[key] = status

        self.state.finished_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.state.duration = time.time() - started
        self.state.summary = self.state.counts()

        self._generate_reports()
        self._print_summary()
        Logger.detach_file()
        return self.state

    # ------------------------------------------------------------------
    def _generate_reports(self) -> None:
        generator = ReportGenerator(self.state, self.out, self.cfg, self.log)
        try:
            paths = generator.generate()
            self.report_paths = {k: str(v) for k, v in paths.items()}
            self.log.success("reports written to %s", self.out.dir("reports"))
        except Exception as exc:  # noqa: BLE001
            self.state.errors.append(f"report: {exc}")
            self.log.error("report generation failed: %s", exc)

    # ------------------------------------------------------------------
    def _print_banner(self, modules: List[str]) -> None:
        from .. import BANNER, __version__

        if Colors.enabled:
            print(Colors.cyan(BANNER))
        print(Colors.info(f" target : {self.cfg.domain}"))
        print(Colors.paint(f" output : {self.out.target_dir}", "dim"))
        print(Colors.paint(
            f" mode   : {'passive' if self.cfg.passive_only else 'active'} | "
            f"threads {self.cfg.threads} | rate {self.cfg.rate_limit:g}/s | "
            f"timeout {self.cfg.timeout:g}s", "dim"))
        print(Colors.paint(f" modules: {', '.join(modules)}", "dim"))
        print()

    def _print_module_header(self, index: int, total: int, label: str) -> None:
        header = f"[{index}/{total}] {label}"
        line = "─" * 64
        print()
        print(Colors.paint(line, "grey"))
        print(" " + Colors.bold(Colors.cyan(header)))
        print(Colors.paint(line, "grey"))

    def _print_summary(self) -> None:
        state = self.state
        counts = state.counts()
        severity = {level: sum(1 for f in state.findings if f["severity"] == level)
                    for level in ("high", "medium", "low", "info")}
        print()
        print(Colors.paint("═" * 64, "grey"))
        print(" " + Colors.bold("SCAN COMPLETE"))
        print(Colors.paint("═" * 64, "grey"))
        rows = [
            ("Duration", human_duration(state.duration)),
            ("Subdomains", counts["subdomains"]),
            ("Resolved hosts", counts["resolved"]),
            ("Live hosts", counts["live_hosts"]),
            ("Open ports", counts["open_ports"]),
            ("Technologies", counts["technologies"]),
            ("URLs", counts["urls"]),
            ("API endpoints", counts["api_endpoints"]),
            ("JS files / secrets", f"{counts['js_files']} / {counts['js_secrets']}"),
            ("Content paths", counts["content_paths"]),
        ]
        width = max(len(r[0]) for r in rows)
        for label, value in rows:
            print(f"  {Colors.grey(label.ljust(width))}  {Colors.bold(str(value))}")
        print()
        print("  " + Colors.paint(
            f"findings: HIGH {severity['high']} | MEDIUM {severity['medium']} | "
            f"LOW {severity['low']} | INFO {severity['info']}", "bold"))
        print()
        print(f"  {Colors.grey('results')}  {self.out.target_dir}")
        for key in ("summary", "json", "html"):
            if key in self.report_paths:
                print(f"  {Colors.grey(key.ljust(7))}  {self.report_paths[key]}")
        if state.errors:
            print()
            print("  " + Colors.warn(f"{len(state.errors)} non-fatal error(s) recorded - see summary.txt"))
        print()
        print("  " + Colors.dim("Reconnaissance data only - verify findings manually."))
        print()