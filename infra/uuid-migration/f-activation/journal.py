"""Durable private attempt claim and hash-chained phase evidence, no SQL/params."""

from __future__ import annotations

import json
import os
import re
import stat
from datetime import UTC, datetime
from pathlib import Path

from security import require, sha

PHASES = {
    "CLAIMED",
    "CONNECT_REQUESTED",
    "CONNECTED",
    "PREFLIGHT_ACCEPTED",
    "LOCKED",
    "BODY_REQUESTED",
    "BODY_ACKNOWLEDGED",
    "MARKER_ACKNOWLEDGED",
    "COMMIT_REQUESTED",
    "COMMIT_ACKNOWLEDGED",
    "ROLLBACK_ACKNOWLEDGED",
    "CLOSED",
    "DISPOSED",
    "READBACK_ACCEPTED",
    "STOP",
    "SQL_REQUESTED",
    "CONTROL_REQUESTED",
}
FIELDS = {
    "manifest_sha256",
    "action_sha256",
    "category",
    "count",
    "sql_sha256",
    "control",
    "outcome",
    "exception",
    "sqlstate",
}


def safe_error(error):
    name, state = type(error).__name__, getattr(error, "sqlstate", None)
    return {
        "exception": name if re.fullmatch("[A-Za-z_][A-Za-z_0-9]{0,79}", name) else "Error",
        "sqlstate": state if isinstance(state, str) and re.fullmatch("[A-Z0-9]{5}", state) else None,
    }


class Journal:
    """O_EXCL claim survives a crash; reusing it refuses rather than retrying.

    No truncation/recovery/cleanup API. Approval renewal cannot erase a claim;
    independent reconciliation must examine the previous per-unit claim too.
    directory must be a dedicated private unit directory allocated at approval.
    """

    def __init__(self, directory, manifest_sha256, action):
        path = Path(directory)
        require(path.is_absolute() and all(not p.is_symlink() for p in (path, *path.parents)), "Unsafe journal path")
        s = path.stat()
        require(stat.S_IMODE(s.st_mode) == 0o700 and s.st_uid == os.getuid(), "Private journal directory required")
        require(
            bool(re.fullmatch("[0-9a-f]{64}", manifest_sha256)) and isinstance(action, str) and action,
            "Original authority hash/action required",
        )
        self.path = path / "unit-attempt.jsonl"
        self.fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self.previous = "0" * 64
        self.sequence = 0
        try:
            self.record("CLAIMED", manifest_sha256=manifest_sha256, action_sha256=sha(action.encode()))
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except BaseException:
            self.close()
            raise

    def record(self, phase, **fields):
        require(phase in PHASES and set(fields) <= FIELDS, "Unsafe evidence field")
        require(
            all(
                v is None
                or type(v) is int
                or isinstance(v, str)
                and len(v) <= 128
                and re.fullmatch("[A-Za-z0-9_:.-]+", v)
                for v in fields.values()
            ),
            "Unsafe evidence value",
        )
        row = {
            "sequence": self.sequence,
            "utc": datetime.now(UTC).isoformat(),
            "phase": phase,
            "previous_sha256": self.previous,
            **fields,
        }
        raw = json.dumps(row, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        require(os.write(self.fd, raw) == len(raw), "Short evidence write")
        os.fsync(self.fd)
        self.previous = sha(raw)
        self.sequence += 1

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
