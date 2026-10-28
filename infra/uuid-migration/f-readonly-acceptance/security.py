"""Inert, source-specific F read-only authority and protected-file contracts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path("/Users/ferozebasha/sbom")
FOLDER = ROOT / "infra/uuid-migration/f-readonly-acceptance"
SECRET = "/Users/ferozebasha/.sbom-uuid-w2-f/postgres-password"
TARGET = {
    "host": "127.0.0.1",
    "hostaddr": "127.0.0.1",
    "port": 56043,
    "dbname": "uuid_w2_f_fresh",
    "user": "uuid_w2_f_bootstrap",
}
LIMITS = {
    "attempts": 1,
    "simultaneous_connections": 1,
    "queries": 40,
    "controls": 2,
    "connect_seconds": 5,
    "statement_ms": 2000,
    "lock_ms": 250,
    "idle_ms": 5000,
    "cooperative_seconds": 60,
    "rows_per_query": 1024,
    "total_rows": 8192,
}
REVIEWS = (
    "source_reviewed",
    "read_only_session_approved",
    "credential_provenance_reviewed",
    "privileged_bootstrap_read_reviewed",
    "network_egress_reviewed",
)
FIELDS = {
    "schema",
    "accepted",
    "repository",
    "created_at",
    "expires_at",
    "target",
    "budgets",
    "sources",
    "infrastructure_reference",
    "credential_metadata",
    "historical_evidence",
    "sql_sha256",
    "unknown_database_identity",
    "operator",
    "approvals",
    "integrity_attestations",
    "integrity_approvals",
    "review_observations",
}


HISTORICAL = {
    "W24C": {
        "path": "/Users/ferozebasha/.sbom-uuid-w2-review/w24c-20261019T053937635357Z/w24c-source-review-package.json",
        "sha256": "6e7b633e17ea2ff63c137c8f6829222999bae45b5dca6309122476da1f8b14df",
    },
    "W24D": {
        "path": "/Users/ferozebasha/.sbom-uuid-w2-review/w24d-20261019T060938878326Z/infrastructure-acceptance.json",
        "sha256": "b7fbc90503ffcfd812f6fbd58767ade79a926539b7d87add704b3a6a9b2923d5",
    },
}


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(raw):
    def pairs(items):
        result = {}
        for k, v in items:
            require(k not in result, "Duplicate JSON key")
            result[k] = v
        return result

    return json.loads(
        raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON"))
    )


def private_bytes(path, expected):
    require(isinstance(expected, str) and re.fullmatch("[0-9a-f]{64}", expected), "Approved raw byte hash required")
    p = Path(path)
    require(p.is_absolute() and ".." not in p.parts and not p.is_relative_to(ROOT), "Private path required")
    chain = [q.lstat() for q in (p, *p.parents)]
    require(all(not stat.S_ISLNK(s.st_mode) for s in chain), "Symlink private path")
    s, parent = chain[:2]
    require(
        stat.S_ISREG(s.st_mode)
        and s.st_nlink == 1
        and s.st_uid == os.getuid()
        and stat.S_IMODE(s.st_mode) == 0o600
        and 0 < s.st_size <= 2097152
        and stat.S_IMODE(parent.st_mode) == 0o700
        and parent.st_uid == os.getuid(),
        "Private file provenance",
    )
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(
            (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns),
            "Private file replaced",
        )
        raw = bytearray()
        while len(raw) <= 2097152:
            chunk = os.read(fd, min(65536, 2097153 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(fd)

        def stable(x):
            return (x.st_mode, x.st_uid, x.st_nlink, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns)

        require(
            stable(before) == stable(after) == stable(s) == stable(p.lstat()) and sha(raw) == expected,
            "Private bytes changed",
        )
        return bytes(raw)
    finally:
        os.close(fd)


def source_bundle():
    require(not any(p.is_symlink() for p in (FOLDER, *FOLDER.parents)), "Symlink source directory")
    files = [p for p in FOLDER.iterdir() if p.is_file() and p.suffix in {".py", ".json", ".md"}]
    require(files and all(not p.is_symlink() for p in files), "Invalid source bundle")
    return {p.name: sha(p.read_bytes()) for p in sorted(files)}


def credential_metadata(path=SECRET):
    require(path == SECRET, "Only F credential metadata")
    p = Path(path)
    items = [x.lstat() for x in (p, *p.parents)]
    require(all(not stat.S_ISLNK(s.st_mode) for s in items), "Symlink credential")
    s, parent = items[:2]
    require(
        stat.S_ISREG(s.st_mode)
        and s.st_nlink == 1
        and s.st_uid == os.getuid()
        and stat.S_IMODE(s.st_mode) == 0o600
        and stat.S_IMODE(parent.st_mode) == 0o700
        and parent.st_uid == os.getuid()
        and s.st_size == 64,
        "F credential provenance",
    )
    return {
        "path": path,
        "uid": s.st_uid,
        "gid": s.st_gid,
        "inode": s.st_ino,
        "size": s.st_size,
        "mode": 0o600,
        "parent_mode": 0o700,
        "nlink": s.st_nlink,
        "mtime_ns": s.st_mtime_ns,
        "ctime_ns": s.st_ctime_ns,
    }


def clean_environment(env):
    require(
        set(env) <= {"HOME", "PATH", "LC_ALL", "PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE"},
        "Use explicitly clean environment; PG/service/target overrides forbidden",
    )
    return dict(env)


def validate(plan, *, now=None, live=False, reference=None, sources=None, sql_pins=None):
    require(
        type(plan) is dict
        and set(plan) == FIELDS
        and plan["schema"] == "w24e-f-readonly-v1"
        and plan["accepted"] is False,
        "Wrong manifest schema/fields",
    )
    require(
        plan["repository"] == str(ROOT) and plan["target"] == TARGET and plan["budgets"] == LIMITS,
        "F-only target/budget mismatch",
    )
    expiry = datetime.fromisoformat(plan["expires_at"])
    created = datetime.fromisoformat(plan["created_at"])
    require(
        expiry.utcoffset() is not None
        and expiry.utcoffset().total_seconds() == 0
        and created.utcoffset() is not None
        and expiry > created
        and expiry > (now or datetime.now(UTC)),
        "Expired/non-UTC approval",
    )
    require(plan["sources"] == (sources if sources is not None else source_bundle()), "Source pin mismatch")
    require(plan["sql_sha256"] == sql_pins, "SQL allowlist mismatch")
    require(
        plan["unknown_database_identity"]
        == {
            "system_identifier": None,
            "database_oid": None,
            "authenticated_version": None,
            "catalog_fingerprint": None,
            "alembic_marker": None,
        },
        "Do not invent first-observation database identity",
    )
    require(
        set(plan["operator"]) == set(REVIEWS) and all(type(v) is bool for v in plan["operator"].values()),
        "Invalid review flags",
    )
    require(
        plan["integrity_attestations"] == [False] * 7 and plan["integrity_approvals"] == {}, "Integrity not authorized"
    )
    require(type(plan["approvals"]) is dict and set(plan["approvals"]) <= {"read_only_execute"}, "Unexpected action")
    require(plan["historical_evidence"] == HISTORICAL, "Historical evidence references changed")
    resource = plan["infrastructure_reference"]
    require(
        set(resource) == {"path", "sha256"}
        and Path(resource["path"]).is_absolute()
        and Path(resource["path"]).name == "infrastructure-baseline.json"
        and re.fullmatch("[0-9a-f]{64}", resource["sha256"]),
        "Infrastructure evidence reference",
    )
    require(plan["credential_metadata"].get("path") == SECRET, "Wrong credential provenance")
    if live:
        require(all(plan["operator"].values()), "Independent source/read-only reviews required")
        require(
            isinstance(reference, str)
            and re.fullmatch(r"W24E-F-READONLY-[A-Z0-9-]{1,64}", reference)
            and plan["approvals"] == {"read_only_execute": reference},
            "Distinct F action approval required",
        )
    return plan


class Authority:
    def __init__(self, path, expected, reference, sql_pins):
        self.path, self.expected, self.reference, self.sql_pins = path, expected, reference, sql_pins
        self.raw = private_bytes(path, expected)
        self.plan = unique(self.raw)
        validate(self.plan, live=True, reference=reference, sql_pins=sql_pins)
        self.recheck()

    def recheck(self):
        raw = private_bytes(self.path, self.expected)
        require(raw == self.raw and unique(raw) == self.plan, "Manifest substitution before authentication/observation")
        validate(self.plan, live=True, reference=self.reference, sql_pins=self.sql_pins)
        for evidence in HISTORICAL.values():
            private_bytes(evidence["path"], evidence["sha256"])
        return self.plan


def safe_error(error, secret=b""):
    state = getattr(error, "sqlstate", None)
    primary = getattr(getattr(error, "diag", None), "message_primary", None)
    value = primary if isinstance(primary, str) and primary else str(error)
    if secret:
        value = value.replace(bytes(secret).decode("ascii", errors="ignore"), "[REDACTED]")
    value = re.sub(r"(?i)(postgres(?:ql)?://)[^\s]+", r"\1[REDACTED]", value)
    value = re.sub(
        r"(?i)\b(password|passfile|token|secret|service|sslkey)\s*=\s*(?:\x27[^\x27]*\x27|\x22[^\x22]*\x22|\S+)",
        r"\1=[REDACTED]",
        value,
    )
    value = "".join(c if 32 <= ord(c) < 127 else " " for c in value)[:256]
    # Unknown diagnostics containing remaining credential-shaped material are not persisted.
    if re.search(r"(?i)(SCRAM-SHA|bearer\s|BEGIN .*PRIVATE KEY)", value):
        value = "UNCLASSIFIED_REDACTED"
    return {
        "exception": type(error).__name__[:64],
        "sqlstate": state if isinstance(state, str) and re.fullmatch("[A-Z0-9]{5}", state) else None,
        "primary": value,
    }
