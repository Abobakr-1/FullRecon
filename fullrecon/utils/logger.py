"""Console + file logging with per-module context."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from threading import Lock

from .colors import Colors, strip_ansi

LOG_FORMAT_FILE = "%(asctime)s [%(levelname)-7s] %(name)s: %(message)s"
LOG_FORMAT_DATE = "%Y-%m-%d %H:%M:%S"

_LEVEL_STYLE = {
    "DEBUG": ("grey", "DBG"),
    "INFO": ("cyan", "INF"),
    "SUCCESS": ("green", "OK "),
    "WARNING": ("yellow", "WRN"),
    "ERROR": ("red", "ERR"),
    "CRITICAL": ("bright_red", "CRT"),
}

SUCCESS = 25
logging.addLevelName(SUCCESS, "SUCCESS")


class _ConsoleFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        colour, tag = _LEVEL_STYLE.get(record.levelname, ("white", record.levelname[:3]))
        name = record.name.split(".")[-1]
        message = record.getMessage()
        if record.exc_info:
            message = f"{message}\n{self.formatException(record.exc_info)}"
        return "{stamp} {tag} {name} {message}".format(
            stamp=Colors.grey(self.formatTime(record, "%H:%M:%S")),
            tag=Colors.paint(tag, colour, "bold"),
            name=Colors.grey(f"[{name}]"),
            message=Colors.paint(message, colour) if record.levelno >= logging.WARNING else message,
        )


class _FileFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        return strip_ansi(message)


class Logger:
    """Thin wrapper that fans a logger out to console and a run log file."""

    _lock = Lock()
    _file_handler: logging.FileHandler | None = None
    _root_ready = False

    def __init__(self, name: str = "fullrecon"):
        self.name = name if name.startswith("fullrecon") else f"fullrecon.{name}"
        self._logger = logging.getLogger(self.name)
        if not self._logger.handlers:
            self._logger.propagate = False
            self._logger.setLevel(logging.DEBUG)
            console = logging.StreamHandler(sys.stdout)
            console.setLevel(logging.INFO)
            console.setFormatter(_ConsoleFormatter(datefmt=LOG_FORMAT_DATE))
            self._logger.addHandler(console)

    # ------------------------------------------------------------------
    @classmethod
    def attach_file(cls, path: str | Path, level: int = logging.DEBUG) -> None:
        """Attach a shared file handler to the ``fullrecon`` root logger."""
        with cls._lock:
            if cls._file_handler is not None:
                logging.getLogger("fullrecon").removeHandler(cls._file_handler)
                try:
                    cls._file_handler.close()
                except Exception:
                    pass
                cls._file_handler = None
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            handler = logging.FileHandler(path, encoding="utf-8")
            handler.setLevel(level)
            handler.setFormatter(_FileFormatter(LOG_FORMAT_FILE, datefmt=LOG_FORMAT_DATE))
            root = logging.getLogger("fullrecon")
            root.setLevel(logging.DEBUG)
            root.addHandler(handler)
            cls._file_handler = handler

    @classmethod
    def detach_file(cls) -> None:
        with cls._lock:
            if cls._file_handler is not None:
                logging.getLogger("fullrecon").removeHandler(cls._file_handler)
                cls._file_handler.close()
                cls._file_handler = None

    # ------------------------------------------------------------------
    def debug(self, message: str, *args) -> None:
        self._logger.debug(message, *args)

    def verbose(self, message: str, *args) -> None:
        """Debug-level detail that is shown when ``-v`` is used."""
        self._logger.log(logging.DEBUG, message, *args)

    def info(self, message: str, *args) -> None:
        self._logger.info(message, *args)

    def success(self, message: str, *args) -> None:
        self._logger.log(SUCCESS, message, *args)

    def warning(self, message: str, *args) -> None:
        self._logger.warning(message, *args)

    def error(self, message: str, *args) -> None:
        self._logger.error(message, *args)

    def critical(self, message: str, *args) -> None:
        self._logger.critical(message, *args)

    def exception(self, message: str, *args) -> None:
        self._logger.exception(message, *args)


def get_logger(name: str = "fullrecon") -> Logger:
    return Logger(name)


def enable_verbose(verbose: bool = True) -> None:
    """Show DEBUG output on the console when -v is passed."""
    level = logging.DEBUG if verbose else logging.INFO
    for name, logger in logging.Logger.manager.loggerDict.items():
        if name.startswith("fullrecon") and isinstance(logger, logging.Logger):
            for handler in logger.handlers:
                if isinstance(handler, logging.StreamHandler) and not isinstance(
                    handler, logging.FileHandler
                ):
                    handler.setLevel(level)


def silence_external(level: int = logging.WARNING) -> None:
    """Reduce noise from third-party libraries."""
    for noisy in ("urllib3", "requests", "charset_normalizer"):
        logging.getLogger(noisy).setLevel(level)