"""Per-target result directory management.

Layout (created automatically)::

    FullRecon-Results/<target>/
        01-Subdomains/ ... 10-Reports/  logs/  raw/
        manifest.json

A scan directory is ``<target>`` by default.  With ``--timestamped`` each run
gets ``<target>/<YYYYmmdd-HHMMSS>/``.  Existing non-empty target directories are
never overwritten silently.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from ..config import OUTPUT_DIRS, Config
from ..utils.helpers import ensure_dir, write_lines, write_text


class OutputExists(Exception):
    """Raised when a result directory already exists and overwrite is denied."""


class OutputManager:
    def __init__(self, cfg: Config, logger=None) -> None:
        self.cfg = cfg
        self.log = logger
        self.base = Path(cfg.out_dir).expanduser().resolve()
        stamp = time.strftime("%Y%m%d-%H%M%S")
        self.scan_time = stamp
        target_dir = self.base / cfg.domain
        if cfg.timestamped:
            target_dir = target_dir / stamp
        self.target_dir = target_dir
        self.written: List[str] = []
        self._prepared = False

    # ------------------------------------------------------------------
    def prepare(self, confirm=None) -> Path:
        """Create the directory tree, honouring the overwrite policy.

        *confirm* is an optional callable ``(path) -> bool`` used to ask the
        user for permission when results already exist.
        """
        if self._prepared:
            return self.target_dir

        existing = self.target_dir.exists() and any(self.target_dir.iterdir())
        if existing:
            allowed = bool(self.cfg.overwrite)
            if not allowed and confirm is not None:
                allowed = bool(confirm(self.target_dir))
            if not allowed:
                raise OutputExists(
                    f"results already exist at {self.target_dir} "
                    "(use --overwrite or --timestamped)"
                )
            # Remove only the parseable target directory, never the base dir.
            if self.target_dir.resolve() == self.base.resolve():
                raise OutputExists(
                    f"refusing to overwrite {self.target_dir}: it is the results root"
                )
            shutil.rmtree(self.target_dir)

        ensure_dir(self.target_dir)
        for name, folder in OUTPUT_DIRS.items():
            ensure_dir(self.target_dir / folder)
        self._prepared = True
        self._write_readme()
        return self.target_dir

    # ------------------------------------------------------------------
    def dir(self, name: str) -> Path:
        folder = OUTPUT_DIRS.get(name, name)
        path = self.target_dir / folder
        ensure_dir(path)
        return path

    def path(self, name: str, filename: str) -> Path:
        return self.dir(name) / filename

    # -- writers --------------------------------------------------------
    def write(self, name: str, filename: str, lines: Iterable[str]) -> int:
        target = self.path(name, filename)
        count = write_lines(target, lines)
        self._record(target)
        return count

    def write_text(self, name: str, filename: str, text: str) -> Path:
        target = self.path(name, filename)
        write_text(target, text)
        self._record(target)
        return target

    def write_json(self, name: str, filename: str, payload) -> Path:
        target = self.path(name, filename)
        write_text(target, json.dumps(payload, indent=2, ensure_ascii=False, default=str))
        self._record(target)
        return target

    def write_raw(self, filename: str, lines: Iterable[str]) -> int:
        target = self.path("raw", filename)
        count = write_lines(target, lines)
        self._record(target)
        return count

    # -- helpers --------------------------------------------------------
    def _record(self, path: Path) -> None:
        try:
            rel = str(path.relative_to(self.target_dir)).replace("\\", "/")
        except ValueError:  # pragma: no cover
            rel = str(path)
        if rel not in self.written:
            self.written.append(rel)

    def log_path(self) -> Path:
        return self.path("logs", "fullrecon.log")

    def summary(self) -> Dict[str, object]:
        files = []
        for rel in sorted(self.written):
            full = self.target_dir / rel
            files.append({
                "path": rel,
                "bytes": full.stat().st_size if full.exists() else 0,
                "lines": self._count_lines(full),
            })
        return {
            "target": self.cfg.domain,
            "scan_time": self.scan_time,
            "directory": str(self.target_dir),
            "file_count": len(files),
            "files": files,
        }

    @staticmethod
    def _count_lines(path: Path) -> int:
        try:
            if path.stat().st_size > 5 * 1024 * 1024:
                return -1
            with open(path, "rb") as fh:
                return sum(1 for _ in fh)
        except OSError:
            return 0

    def write_manifest(self) -> Path:
        payload = self.summary()
        target = self.path("reports", "manifest.json")
        write_text(target, json.dumps(payload, indent=2))
        return target

    def tree_text(self) -> str:
        """Render the result tree for terminal display."""
        lines = [str(self.target_dir.name) + "/"]
        try:
            entries = sorted(self.target_dir.iterdir())
        except OSError:
            return "\n".join(lines)
        for entry in entries:
            if entry.is_dir():
                files = sorted(p for p in entry.iterdir() if p.is_file())
                lines.append(f"├── {entry.name}/")
                for i, f in enumerate(files):
                    branch = "└──" if i == len(files) - 1 else "├──"
                    lines.append(f"│   {branch} {f.name}")
            else:
                lines.append(f"├── {entry.name}")
        return "\n".join(lines)

    def _write_readme(self) -> None:
        text = (
            f"FullRecon results for {self.cfg.domain}\n"
            f"scan started: {self.scan_time} UTC\n\n"
            "Folders are numbered in pipeline order:\n"
            "01-Subdomains, 02-DNS, 03-Live-Hosts, 04-Ports, 05-Technologies,\n"
            "06-URLs, 07-API, 08-JavaScript, 09-Content-Discovery, 10-Reports.\n"
            "raw/ holds unprocessed source responses, logs/ holds the run log.\n\n"
            "Only scan systems you are authorized to test.\n"
        )
        write_text(self.target_dir / "README.txt", text)