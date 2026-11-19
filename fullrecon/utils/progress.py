"""Dependency-free progress bar and spinner-ish status printer."""

from __future__ import annotations

import sys
import time
from typing import Optional, TextIO

from .colors import Colors, strip_ansi


class ProgressBar:
    """Simple single-line progress bar.

    Rendered on a TTY; when output is redirected it prints nothing per-tick so
    piped logs stay clean (call ``close()`` to emit one final summary line).
    """

    def __init__(
        self,
        total: int,
        label: str = "",
        width: int = 32,
        stream: Optional[TextIO] = None,
        enabled: Optional[bool] = None,
    ) -> None:
        self.total = max(int(total), 0)
        self.label = label
        self.width = width
        self.stream = stream or sys.stdout
        self.enabled = self.stream.isatty() if enabled is None else enabled
        self.count = 0
        self.started = time.time()
        self._last_render = 0.0
        self._closed = False

    # ------------------------------------------------------------------
    def update(self, step: int = 1, label: Optional[str] = None) -> None:
        self.count += step
        if label is not None:
            self.label = label
        if not self.enabled:
            return
        now = time.time()
        if now - self._last_render < 0.05 and self.count < self.total:
            return
        self._last_render = now
        self._render()

    def set_label(self, label: str) -> None:
        self.label = label

    def _render(self) -> None:
        total = self.total or 1
        ratio = min(self.count / total, 1.0)
        filled = int(self.width * ratio)
        bar = "█" * filled + "░" * (self.width - filled)
        percent = int(ratio * 100)
        elapsed = time.time() - self.started
        eta = ""
        if ratio > 0.02 and self.count < total:
            remaining = elapsed / ratio - elapsed
            eta = f" ETA {remaining:4.0f}s"
        line = "\r{label} [{bar}] {pct:3d}% {count}/{total}{eta}".format(
            label=self.label[:28].ljust(28),
            bar=Colors.cyan(bar),
            pct=percent,
            count=self.count,
            total=self.total,
            eta=eta,
        )
        self.stream.write(line)
        self.stream.flush()
        if self.count >= self.total:
            self.stream.write("\n")
            self._closed = True

    def close(self, message: Optional[str] = None) -> None:
        if self._closed:
            if message and not self.enabled:
                self.stream.write(message + "\n")
                self.stream.flush()
            return
        self._closed = True
        if self.enabled:
            if self.count < self.total:
                self.total = max(self.count, 1)
                self._render()
            elif message:
                self.stream.write("\n" + message + "\n")
                self.stream.flush()
            else:
                self.stream.write("\n")
                self.stream.flush()
        elif message:
            self.stream.write(message + "\n")
            self.stream.flush()

    def __enter__(self) -> "ProgressBar":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()


def human_duration(seconds: float) -> str:
    seconds = max(float(seconds), 0.0)
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{int(minutes)}m {sec:.0f}s"
    hours, minutes = divmod(int(minutes), 60)
    return f"{hours}h {minutes}m"


def print_header(text: str, stream: Optional[TextIO] = None) -> None:
    stream = stream or sys.stdout
    line = "─" * max(len(strip_ansi(text)) + 2, 24)
    stream.write("\n" + Colors.paint(line, "grey") + "\n")
    stream.write(" " + Colors.bold(text) + "\n")
    stream.write(Colors.paint(line, "grey") + "\n")
    stream.flush()