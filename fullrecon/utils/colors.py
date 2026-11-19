"""ANSI colour helpers with automatic TTY / NO_COLOR detection."""

from __future__ import annotations

import os
import sys

_CODES = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "italic": "\033[3m",
    "underline": "\033[4m",
    "black": "\033[30m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[37m",
    "grey": "\033[90m",
    "bright_red": "\033[91m",
    "bright_green": "\033[92m",
    "bright_yellow": "\033[93m",
    "bright_blue": "\033[94m",
    "bright_magenta": "\033[95m",
    "bright_cyan": "\033[96m",
}


def _supports_colour(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if os.environ.get("TERM") in ("dumb", ""):
        return False
    try:
        return bool(stream.isatty())
    except Exception:
        return False


class Colors:
    """Namespace holding a bool flag plus a colourise helper."""

    enabled = _supports_colour()

    @classmethod
    def configure(cls, enabled: bool) -> None:
        cls.enabled = enabled

    @classmethod
    def paint(cls, text: str, *styles: str) -> str:
        if not cls.enabled or not styles:
            return text
        prefix = "".join(_CODES.get(s, "") for s in styles)
        return f"{prefix}{text}{_CODES['reset']}"

    # convenience wrappers ------------------------------------------------
    @classmethod
    def red(cls, text: str) -> str:
        return cls.paint(text, "red")

    @classmethod
    def green(cls, text: str) -> str:
        return cls.paint(text, "green")

    @classmethod
    def yellow(cls, text: str) -> str:
        return cls.paint(text, "yellow")

    @classmethod
    def blue(cls, text: str) -> str:
        return cls.paint(text, "blue")

    @classmethod
    def magenta(cls, text: str) -> str:
        return cls.paint(text, "magenta")

    @classmethod
    def cyan(cls, text: str) -> str:
        return cls.paint(text, "cyan")

    @classmethod
    def grey(cls, text: str) -> str:
        return cls.paint(text, "grey")

    @classmethod
    def bold(cls, text: str) -> str:
        return cls.paint(text, "bold")

    @classmethod
    def dim(cls, text: str) -> str:
        return cls.paint(text, "dim")

    @classmethod
    def ok(cls, text: str) -> str:
        return cls.paint(text, "bold", "green")

    @classmethod
    def warn(cls, text: str) -> str:
        return cls.paint(text, "bold", "yellow")

    @classmethod
    def err(cls, text: str) -> str:
        return cls.paint(text, "bold", "red")

    @classmethod
    def info(cls, text: str) -> str:
        return cls.paint(text, "bold", "cyan")


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences (used before width calculation)."""
    out = []
    i = 0
    length = len(text)
    while i < length:
        if text[i] == "\033":
            while i < length and text[i] not in "mK":
                i += 1
        else:
            out.append(text[i])
        i += 1
    return "".join(out)