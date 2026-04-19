"""
app/logger.py — Centralized logging configuration for SBOM Analyzer.

Environment variables:
    LOG_LEVEL   : DEBUG | INFO | WARNING | ERROR  (default: INFO)
    LOG_FORMAT  : text | json                      (default: text)
    LOG_FILE    : path to log file                 (default: none — console only)
    LOG_MAX_MB  : max size of each log file in MB  (default: 10)
    LOG_BACKUPS : number of rotated backup files   (default: 5)
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import sys
from datetime import UTC, datetime

# ── ANSI colour codes (disabled automatically on non-TTY) ──────────────────────
_COLOURS = {
    "DEBUG": "\033[36m",  # cyan
    "INFO": "\033[32m",  # green
    "WARNING": "\033[33m",  # yellow
    "ERROR": "\033[31m",  # red
    "CRITICAL": "\033[35m",  # magenta
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def _supports_colour(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty()


# ── Formatters ─────────────────────────────────────────────────────────────────


class ColourTextFormatter(logging.Formatter):
    """Human-readable coloured log lines for terminal output."""

    FMT = "{colour}{bold}[{level:<8}]{reset} {grey}{ts}{reset}  {name}  {colour}{msg}{reset}"

    def __init__(self, use_colour: bool = True):
        super().__init__()
        self._use_colour = use_colour

    def format(self, record: logging.LogRecord) -> str:
        colour = _COLOURS.get(record.levelname, "") if self._use_colour else ""
        reset = _RESET if self._use_colour else ""
        bold = _BOLD if self._use_colour else ""
        grey = "\033[90m" if self._use_colour else ""

        ts = datetime.fromtimestamp(record.created, tz=UTC).strftime("%Y-%m-%d %H:%M:%S")
        msg = record.getMessage()

        if record.exc_info:
            msg += "\n" + self.formatException(record.exc_info)

        return f"{colour}{bold}[{record.levelname:<8}]{reset} {grey}{ts}{reset}  {record.name}  {colour}{msg}{reset}"


class JsonFormatter(logging.Formatter):
    """Structured JSON log lines — ideal for log aggregators (Datadog, CloudWatch, etc.)."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "func": record.funcName,
            "line": record.lineno,
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


# ── Public setup function ──────────────────────────────────────────────────────


def setup_logging(
    level: str | None = None,
    fmt: str | None = None,
    log_file: str | None = None,
    max_bytes: int = 0,
    backup_count: int = 5,
) -> None:
    """
    Configure the root logger once at application startup.

    Args:
        level:        Override LOG_LEVEL env var.
        fmt:          Override LOG_FORMAT env var ("text" or "json").
        log_file:     Override LOG_FILE env var.
        max_bytes:    Override per-file size limit (bytes).
        backup_count: Override LOG_BACKUPS env var.
    """
    level_str = (level or os.getenv("LOG_LEVEL", "INFO")).upper()
    fmt_str = (fmt or os.getenv("LOG_FORMAT", "text")).lower()
    file_path = log_file or os.getenv("LOG_FILE", "")
    max_mb = int(os.getenv("LOG_MAX_MB", "10"))
    backups = int(os.getenv("LOG_BACKUPS", str(backup_count)))
    max_bytes_ = max_bytes or max_mb * 1024 * 1024

    numeric_level = getattr(logging, level_str, logging.INFO)

    root = logging.getLogger()
    root.setLevel(numeric_level)

    # Remove any existing handlers (avoid duplicate logs on reload)
    root.handlers.clear()

    # ── Console handler ─────────────────────────────────────────────────────���──
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(numeric_level)
    if fmt_str == "json":
        console.setFormatter(JsonFormatter())
    else:
        console.setFormatter(ColourTextFormatter(use_colour=_supports_colour(sys.stdout)))
    root.addHandler(console)

    # ── File handler (optional) ────────────────────────────────────────────────
    if file_path:
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            filename=file_path,
            maxBytes=max_bytes_,
            backupCount=backups,
            encoding="utf-8",
        )
        file_handler.setLevel(numeric_level)
        # Always write JSON to file for structured parsing
        file_handler.setFormatter(JsonFormatter())
        root.addHandler(file_handler)

    # ── Re-home uvicorn / fastapi loggers on the root handler ─────────────────
    # Uvicorn installs its own handlers on "uvicorn", "uvicorn.access",
    # "uvicorn.error" and disables propagation — which means NONE of our
    # formatted / filed log lines include its startup or request logs.
    # Clear those handlers and force propagation so every line flows through
    # the single root handler we just configured above.
    for _name in ("uvicorn", "uvicorn.access", "uvicorn.error", "fastapi"):
        _lg = logging.getLogger(_name)
        _lg.handlers.clear()
        _lg.propagate = True
        _lg.setLevel(numeric_level)

    # ── Silence genuinely noisy third-party loggers unless running in DEBUG ───
    # NOTE: uvicorn.access is intentionally NOT silenced here — we want the
    # request line on every call. Only network-layer chatter is throttled.
    if numeric_level > logging.DEBUG:
        for noisy in ("httpx", "httpcore", "urllib3", "asyncio"):
            logging.getLogger(noisy).setLevel(logging.WARNING)

    log = logging.getLogger("sbom.logger")
    log.info(
        "Logging initialised — level=%s  format=%s  file=%s",
        level_str,
        fmt_str,
        file_path or "(console only)",
    )


# ── Convenience getter ─────────────────────────────────────────────────────────


def get_logger(name: str) -> logging.Logger:
    """Return a logger namespaced under 'sbom.<name>'."""
    return logging.getLogger(f"sbom.{name}")
