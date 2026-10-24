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
import re
import sys
import traceback
from contextlib import contextmanager
from contextvars import ContextVar
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

_STANDARD_LOG_RECORD_KEYS = frozenset(logging.makeLogRecord({}).__dict__)
CONTEXT_FIELDS = frozenset(
    {"tenant_id", "project_id", "product_id", "sbom_id", "analysis_run_id", "user_id", "request_id"}
)
_context: ContextVar[dict | None] = ContextVar("logging_context", default=None)
_secret_values: tuple[str, ...] = ()
_sensitive_key = re.compile(r"authorization|cookie|token|password|passwd|secret|private.?key|api.?key|credential", re.I)
_payload_key = re.compile(
    r"^(headers|body|payload|data|sbom_data|sbom_content|vulnerabilities|parameters|params|args|kwargs|task_args|task_kwargs|traceback)$", re.I
)


def _clean(value):
    """Defence in depth for legacy messages; events must still use safe fields."""
    if isinstance(value, dict):
        return {
            str(k): "[REDACTED]" if _sensitive_key.search(str(k)) or _payload_key.search(str(k)) else _clean(v)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_clean(v) for v in value]
    if isinstance(value, BaseException):
        return type(value).__name__
    if not isinstance(value, (str, int, float, bool, type(None))):
        return f"<{type(value).__name__}>"
    if not isinstance(value, str):
        return value
    value = re.sub(
        r"-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|$)",
        "[REDACTED PRIVATE KEY]",
        value,
        flags=re.S,
    )
    value = re.sub(r"(?i)\b(Bearer|Basic)\s+[^\s,;\"']+", r"\1 [REDACTED]", value)
    value = re.sub(r"(?im)\b(authorization|(?:set-)?cookie)\s*:\s*[^\r\n]+", r"\1: [REDACTED]", value)
    value = re.sub(r"(?i)([a-z][a-z0-9+.-]*://)[^\s/@]+:[^\s/@]+@", r"\1[REDACTED]@", value)
    value = re.sub(r"(https?://[^\s?\"']+)\?[^\s\"']*", r"\1?[REDACTED]", value)
    value = re.sub(
        r"(?i)(authorization|cookie|access_token|refresh_token|password|passwd|secret|private_key|api_key)([\"']?\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)",
        r"\1\2[REDACTED]",
        value,
    )
    value = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "[REDACTED JWT]", value)
    for secret in _secret_values:
        value = value.replace(secret, "[REDACTED]")
    return value


def current_log_context() -> dict:
    fields = dict(_context.get() or {})
    # Identity is bound by the existing authentication/tenant context; never
    # trust inbound tenant/user headers as an authenticated logging identity.
    from .core.context import get_bound_context

    identity = get_bound_context()
    if identity is not None:
        fields.update({k: getattr(identity, k) for k in ("tenant_id", "user_id") if getattr(identity, k) is not None})
    return fields


@contextmanager
def log_context(**fields):
    """Scoped IDs, propagated by asyncio and reset even when work fails."""
    token = _context.set(
        {**(_context.get() or {}), **{k: v for k, v in fields.items() if k in CONTEXT_FIELDS and v is not None}}
    )
    try:
        yield
    finally:
        _context.reset(token)


def log_event(logger, event: str, *, level=logging.INFO, exc_info=False, **fields):
    """Emit a named event without interpolating payloads into the message."""
    logger.log(
        level,
        event,
        extra={**current_log_context(), **{k: v for k, v in fields.items() if v is not None}, "event": event},
        exc_info=exc_info,
        stacklevel=2,
    )


def _safe_trace(exc: BaseException, seen=None) -> str:
    """Keep stack locations/types, omit exception text, SQL params and locals."""
    seen = set() if seen is None else seen
    if id(exc) in seen:
        return ""
    seen.add(id(exc))
    parts = []
    cause = exc.__cause__ or (None if exc.__suppress_context__ else exc.__context__)
    if cause is not None:
        parts.append(_safe_trace(cause, seen))
    parts.append("Traceback (most recent call last):")
    for frame in traceback.extract_tb(exc.__traceback__):
        parts.append(f'  File "{frame.filename}", line {frame.lineno}, in {frame.name}')
    parts.append(f"{type(exc).__name__}: [exception message omitted]")
    for child in getattr(exc, "exceptions", ()):
        parts.append(_safe_trace(child, seen))
    return str(_clean("\n".join(parts)))


def _record_payload(record):
    if record.exc_info and record.exc_info[1] is not None:
        message = getattr(record, "event", "Exception captured")
    elif record.name.startswith("sqlalchemy"):
        message = "Database diagnostic (statement and parameters omitted)"
    elif record.name == "celery.app.trace":
        # Celery's success template embeds repr(task_result); a result can be
        # a complete report or a provider response. Keep only task metadata.
        message = "Celery task diagnostic (arguments and results omitted)"
    elif record.name == "uvicorn.access" and isinstance(record.args, tuple) and len(record.args) == 5:
        # Uvicorn normally embeds the raw query string, which may hold tokens.
        client, method, target, protocol, status = record.args
        message = f'{client} - "{method} {str(target).split("?", 1)[0]} HTTP/{protocol}" {status}'
    elif isinstance(record.args, tuple) and any(isinstance(arg, BaseException) for arg in record.args):
        # Legacy warning/error calls often interpolate an exception without
        # exc_info. Its message can contain SQL parameters or provider secrets.
        message = str(record.msg) % tuple(type(arg).__name__ if isinstance(arg, BaseException) else arg for arg in record.args)
    else:
        message = record.getMessage()
    payload = {
        "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
        "level": record.levelname,
        "logger": record.name,
        "message": _clean(message),
        "module": record.module,
        "func": record.funcName,
        "line": record.lineno,
        **current_log_context(),
    }
    for key, value in record.__dict__.items():
        if key not in _STANDARD_LOG_RECORD_KEYS and key not in {"message", "asctime"} and value is not None:
            payload[key] = value
    if record.name == "celery.app.trace":
        task_data = getattr(record, "data", None)
        if isinstance(task_data, dict):
            for source, target in (("id", "task_id"), ("name", "task_name"), ("runtime", "runtime")):
                if isinstance(task_data.get(source), (str, int, float)):
                    payload[target] = task_data[source]
    if record.exc_info and record.exc_info[1] is not None:
        payload["exception_type"] = type(record.exc_info[1]).__name__
        payload["exc"] = _safe_trace(record.exc_info[1])
    return _clean(payload)


class SafeStreamHandler(logging.StreamHandler):
    def handleError(self, record):
        # The standard fallback prints the raw message and arguments, which
        # bypasses redaction if formatting itself fails.
        sys.__stderr__.write("SBOM console logging failed; record omitted.\n")


class ProcessSafeRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """Serialize rollover and writes across Celery prefork children on POSIX.

    A fresh sidecar lock FD and log stream per write avoid inherited-lock and
    stale-inode problems after another process rotates. Windows uses the
    standard handler (single process). Keep one replica per file/volume.
    """

    def emit(self, record):
        if os.name != "posix":
            return super().emit(record)
        import fcntl

        try:
            with open(self.baseFilename + ".lock", "a", encoding="utf-8") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                try:
                    if self.stream is not None:
                        self.stream.close()
                        self.stream = None
                    super().emit(record)
                finally:
                    if self.stream is not None:
                        self.stream.close()
                        self.stream = None
                    fcntl.flock(lock, fcntl.LOCK_UN)
        except Exception:
            # Logging failures must not expose a raw LogRecord via handleError.
            sys.__stderr__.write("SBOM file logging failed; check log directory permissions/disk space.\n")

    def handleError(self, record):
        sys.__stderr__.write("SBOM file logging failed; check log directory permissions/disk space.\n")


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
        payload = _record_payload(record)
        msg = payload["message"]
        fields = {
            k: v
            for k, v in payload.items()
            if k not in {"message", "ts", "level", "logger", "module", "func", "line", "exc"}
        }
        if fields:
            msg += " " + json.dumps(fields, ensure_ascii=False, default=str)
        if "exc" in payload:
            msg += "\n" + payload["exc"]

        return f"{colour}{bold}[{record.levelname:<8}]{reset} {grey}{ts}{reset}  {record.name}  {colour}{msg}{reset}"


class JsonFormatter(logging.Formatter):
    """Structured JSON log lines — ideal for log aggregators (Datadog, CloudWatch, etc.)."""

    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(_record_payload(record), ensure_ascii=False, default=str)


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
    global _secret_values
    _secret_values = tuple(
        sorted({v for k, v in os.environ.items() if _sensitive_key.search(k) and len(v) >= 8}, key=len, reverse=True)
    )
    level_str = (level or os.getenv("LOG_LEVEL", "INFO")).upper()
    fmt_str = (fmt or os.getenv("LOG_FORMAT", "text")).lower()
    file_path = log_file or os.getenv("LOG_FILE", "")
    max_mb = int(os.getenv("LOG_MAX_MB", "10"))
    backups = int(os.getenv("LOG_BACKUPS", str(backup_count)))
    max_bytes_ = max_bytes or max_mb * 1024 * 1024

    numeric_level = getattr(logging, level_str, logging.INFO)

    root = logging.getLogger()
    root.setLevel(numeric_level)

    # Replace only our handlers; preserve host/test/telemetry handlers. Close
    # retired streams so lifespan/reload doesn't leak file descriptors.
    for handler in root.handlers[:]:
        if getattr(handler, "_sbom_owned", False):
            root.removeHandler(handler)
            handler.close()

    # ── Console handler ─────────────────────────────────────────────────────���──
    console = SafeStreamHandler(sys.stdout)
    console._sbom_owned = True
    console.setLevel(numeric_level)
    if fmt_str == "json":
        console.setFormatter(JsonFormatter())
    else:
        console.setFormatter(ColourTextFormatter(use_colour=_supports_colour(sys.stdout)))
    root.addHandler(console)

    # ── File handler (optional) ────────────────────────────────────────────────
    if file_path:
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        file_handler = ProcessSafeRotatingFileHandler(
            filename=file_path,
            maxBytes=max_bytes_,
            backupCount=backups,
            encoding="utf-8",
        )
        file_handler._sbom_owned = True
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
    for _name in (
        "app",
        "sbom",
        "uvicorn",
        "uvicorn.access",
        "uvicorn.error",
        "fastapi",
        "celery",
        "celery.task",
        "celery.worker",
        "celery.beat",
        "sqlalchemy",
        "sqlalchemy.engine",
    ):
        _lg = logging.getLogger(_name)
        _lg.handlers.clear()
        _lg.propagate = True
        _lg.disabled = False
        _lg.setLevel(logging.NOTSET)

    # In-process Alembic/fileConfig and other frameworks can disable loggers
    # that already existed at import time. Restoring just their parents does
    # not re-enable those descendants (Logger.disabled is checked first).
    families = ("app", "sbom", "uvicorn", "fastapi", "celery", "sqlalchemy")
    for name, logger in list(logging.root.manager.loggerDict.items()):
        if isinstance(logger, logging.Logger) and any(name == prefix or name.startswith(prefix + ".") for prefix in families):
            logger.disabled = False
            logger.propagate = True

    # Errors propagate without enabling verbose SQL/parameter diagnostics.
    logging.getLogger("sqlalchemy").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

    # ── Silence genuinely noisy third-party loggers unless running in DEBUG ───
    # NOTE: uvicorn.access is intentionally NOT silenced here — we want the
    # request line on every call. Only network-layer chatter is throttled.
    if numeric_level > logging.DEBUG:
        for noisy in ("httpx", "httpcore", "urllib3", "asyncio"):
            logging.getLogger(noisy).setLevel(logging.WARNING)

    log = logging.getLogger("sbom.logger")
    log.info(
        "Logging initialised level=%s console_format=%s file_format=%s log_file=%s max_mb=%s backups=%s",
        level_str,
        fmt_str,
        "json" if file_path else "none",
        file_path or "(console only)",
        max_bytes_ / (1024 * 1024),
        backups,
        extra={
            "event": "logging_initialised",
            "console_format": fmt_str,
            "file_format": "json" if file_path else None,
            "log_level": level_str,
            "log_file": file_path or None,
            "max_size": max_bytes_,
            "max_mb": max_bytes_ / (1024 * 1024),
            "backup_count": backups,
        },
    )


# ── Convenience getter ─────────────────────────────────────────────────────────


def get_logger(name: str) -> logging.Logger:
    """Return a logger namespaced under 'sbom.<name>'."""
    return logging.getLogger(f"sbom.{name}")
