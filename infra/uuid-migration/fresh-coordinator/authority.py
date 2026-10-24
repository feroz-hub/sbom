"""Exact-byte F authority; no target/resource/secret observation is performed."""

from __future__ import annotations

import ipaddress
import os
import re
import stat
from datetime import UTC, datetime
from pathlib import Path

from source_registry import DIRECTORY, digest, discover, next_unit, require, sha, unique_json

TARGET = {
    "target": "F",
    "host": "127.0.0.1",
    "hostaddr": "127.0.0.1",
    "port": 56043,
    "database": "uuid_w2_f_fresh",
    "user": "uuid_w2_f_bootstrap",
    "postgresql": "16.15",
    "project": "sbom-uuid-w2-f",
    "service": "postgres_f",
    "volume": "sbom-uuid-w2-f_f_pgdata",
    "network": "sbom-uuid-w2-f_f_access",
}
ACTIONS = ("unit_validate", "unit_execute", "unit_readback")
REVIEWS = ("sources", "target", "credentials", "security", "references", "writers", "network_egress")
DAEMON = "1f8c7fe5-5972-4adc-8d6e-363a38572be1"
SOCKET = "/Users/ferozebasha/.docker/run/docker.sock"
D_CLUSTER = "7697252084555804711"
FIELDS = {
    "schema",
    "accepted",
    "target",
    "unit",
    "source_sha256",
    "identity",
    "resources",
    "credential_metadata",
    "prefix_sha256",
    "post_sha256",
    "finalization_catalog_sha256",
    "security_sha256",
    "reference_sha256",
    "post_reference_sha256",
    "fresh_metadata",
    "authentication_review",
    "reviews",
    "review_references",
    "approvals",
    "expires_at",
    "budgets",
    "connection",
    "integrity_attestations",
    "integrity_approvals",
}


def hash_value(value):
    return isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value) is not None


def source_bundle(root, registry):
    result = dict(registry["lock"]["sources"])
    folder = Path(root) / DIRECTORY
    for path in sorted(folder.glob("*.py")):
        require(not path.is_symlink(), "Symlink implementation refused")
        result[str(path.relative_to(root))] = sha(path.read_bytes())
    result[DIRECTORY + "/source-lock.v2.json"] = registry["lock_sha256"]
    return result


def connection_contract(unit, *, readback=False):
    b = unit["budgets"]
    return {
        "host": "127.0.0.1",
        "hostaddr": "127.0.0.1",
        "port": 56043,
        "dbname": "uuid_w2_f_fresh",
        "user": "uuid_w2_f_bootstrap",
        "passfile": "/dev/null",
        "sslmode": "disable",
        "gssencmode": "disable",
        "connect_timeout": 5,
        "application_name": "sbom_w23_f_readback" if readback else "sbom_w23_f_unit",
        "autocommit": False,
        "options": f"-c default_transaction_read_only=on -c statement_timeout={b['statement_ms']} -c lock_timeout={b['lock_ms']} -c idle_in_transaction_session_timeout={b['idle_transaction_ms']} -c search_path=pg_catalog -c row_security=on",
    }


def validate(raw, approved_hash, root, previous, requested, action, action_reference, *, now=None):
    require(
        hash_value(approved_hash) and isinstance(raw, bytes) and sha(raw) == approved_hash,
        "Exact operator-approved raw manifest byte hash required",
    )
    p = unique_json(raw)
    require(
        isinstance(p, dict) and set(p) == FIELDS and p["schema"] == "w23-f-unit-v1", "Unknown/missing manifest field"
    )
    registry = discover(root)
    unit = next_unit(registry, previous, requested)
    require(
        p["accepted"] is False and p["unit"] == {"previous": previous, "next": requested},
        "Exact unaccepted single unit required",
    )
    require(p["target"] == TARGET and type(p["target"]["port"]) is int, "Only explicit F target allowed")
    require(p["source_sha256"] == source_bundle(root, registry), "Source/implementation bundle changed")
    require(
        p["budgets"] == unit["budgets"] and all(type(v) is int and v > 0 for v in p["budgets"].values()),
        "Exact per-unit budgets required",
    )
    require(p["connection"] == connection_contract(unit), "Connection contract changed")
    require(
        p["integrity_attestations"] == [False] * 7
        and all(v is False for v in p["integrity_attestations"])
        and p["integrity_approvals"] == {},
        "Integrity testing not authorized",
    )
    require(
        p["reviews"] == dict.fromkeys(REVIEWS, True) and all(v is True for v in p["reviews"].values()),
        "Independent operator reviews pending",
    )
    require(
        isinstance(p["review_references"], dict)
        and set(p["review_references"]) == set(REVIEWS)
        and all(isinstance(v, str) and v.strip() for v in p["review_references"].values()),
        "Review references missing",
    )
    approvals = p["approvals"]
    require(
        isinstance(approvals, dict)
        and set(approvals) <= set(ACTIONS)
        and all(isinstance(v, str) and v.strip() for v in approvals.values())
        and len(set(approvals.values())) == len(approvals)
        and action in ACTIONS
        and isinstance(action_reference, str)
        and bool(action_reference.strip())
        and approvals.get(action) == action_reference,
        "Missing/distinct F action approval required",
    )
    require(all(not re.match(r"W(?:16|17)", v) for v in approvals.values()), "Old D/E approvals refused")
    try:
        expiry = datetime.fromisoformat(p["expires_at"])
        require(
            expiry.utcoffset() is not None
            and expiry.utcoffset().total_seconds() == 0
            and expiry > (now or datetime.now(UTC)),
            "Expired/non-UTC authority",
        )
    except (ValueError, TypeError):
        require(False, "Invalid or expired UTC authority")
    identity = p["identity"]
    require(
        isinstance(identity, dict) and set(identity) == {"system_identifier", "database_oid", "server_ip"},
        "Exact observed F identity required",
    )
    require(
        isinstance(identity["system_identifier"], str)
        and re.fullmatch("[1-9][0-9]{0,19}", identity["system_identifier"])
        and identity["system_identifier"] != D_CLUSTER
        and type(identity["database_oid"]) is int
        and identity["database_oid"] > 0,
        "Distinct F cluster/database required",
    )
    try:
        ip = ipaddress.ip_address(identity["server_ip"])
        require(
            ip.version == 4 and ip.is_private and not ip.is_loopback and not ip.is_unspecified,
            "Verified internal F interface required",
        )
    except (ValueError, TypeError):
        require(False, "Invalid F internal interface")
    resources = p["resources"]
    require(
        isinstance(resources, dict)
        and set(resources)
        == {"daemon_id", "socket", "container_id", "image_id", "volume_identity", "network_id", "started_at"},
        "Exact resource fields required",
    )
    require(
        resources["daemon_id"] == DAEMON
        and resources["socket"] == SOCKET
        and all(hash_value(resources[k]) for k in ("container_id", "volume_identity", "network_id"))
        and re.fullmatch("sha256:[0-9a-f]{64}", str(resources["image_id"]))
        and isinstance(resources["started_at"], str)
        and resources["started_at"],
        "Pinned local F resource identity required",
    )
    for key in ("prefix_sha256", "post_sha256", "security_sha256", "reference_sha256", "post_reference_sha256"):
        require(hash_value(p[key]), "Independent catalog/security/reference hash required")
    require(
        hash_value(p["finalization_catalog_sha256"])
        if unit["kind"] == "uuid_finalize"
        else p["finalization_catalog_sha256"] is None,
        "Wrong finalization catalog format",
    )
    require(
        isinstance(p["fresh_metadata"], dict) if unit["kind"] == "frozen_047" else p["fresh_metadata"] is None,
        "Freshness metadata applicability mismatch",
    )
    credential = p["credential_metadata"]
    require(
        isinstance(credential, dict)
        and set(credential) == {"path", "uid", "inode", "size", "mode", "parent_mode", "nlink", "mtime_ns", "ctime_ns"},
        "Private credential provenance missing",
    )
    require(
        isinstance(credential["path"], str)
        and credential["path"].startswith("/Users/ferozebasha/.sbom-uuid-w2-f/")
        and Path(credential["path"]).name == "postgres-password"
        and ".." not in Path(credential["path"]).parts
        and credential["mode"] == 0o600
        and credential["parent_mode"] == 0o700
        and credential["nlink"] == 1
        and all(
            type(credential[k]) is int and credential[k] > 0 for k in ("uid", "inode", "size", "mtime_ns", "ctime_ns")
        ),
        "F-only private credential metadata required",
    )
    review = p["authentication_review"]
    require(
        isinstance(review, dict) and set(review) == {"path", "sha256"}, "Independent authentication evidence missing"
    )
    auth_raw = private_bytes(review["path"], review["sha256"])
    auth_record = unique_json(auth_raw)
    require(
        isinstance(auth_record, dict)
        and set(auth_record)
        == {"schema", "scope", "target", "identity", "resource_sha256", "evidence_sha256", "expires_at"},
        "Authentication review format invalid",
    )
    require(
        auth_record["schema"] == "w23-independent-auth-review-v1"
        and auth_record["scope"] == "effective_password_authentication"
        and auth_record["target"] == TARGET
        and auth_record["identity"] == identity
        and auth_record["resource_sha256"] == digest(resources)
        and hash_value(auth_record["evidence_sha256"]),
        "Current HBA file/manifest attestation is not independent effective-auth evidence",
    )
    try:
        auth_expiry = datetime.fromisoformat(auth_record["expires_at"])
        require(
            auth_expiry.utcoffset() is not None
            and auth_expiry.utcoffset().total_seconds() == 0
            and auth_expiry > (now or datetime.now(UTC)),
            "Independent authentication review expired",
        )
    except (ValueError, TypeError):
        require(False, "Invalid authentication review expiry")
    return p, registry, unit


def private_bytes(path, approved_hash):
    require(hash_value(approved_hash), "Operator-approved manifest byte hash required before runtime access")
    path = Path(path)
    require(
        path.is_absolute()
        and path.suffix == ".json"
        and ".." not in path.parts
        and all(not x.is_symlink() for x in (path, *path.parents)),
        "Private absolute nonsymlink JSON required",
    )
    parent = path.parent.stat()
    require(
        parent.st_uid == os.getuid() and stat.S_IMODE(parent.st_mode) == 0o700, "Private0700 review directory required"
    )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        require(
            stat.S_ISREG(s.st_mode)
            and s.st_nlink == 1
            and s.st_uid == os.getuid()
            and stat.S_IMODE(s.st_mode) == 0o600
            and s.st_size <= 1024 * 1024,
            "Private0600 regular single-link manifest required",
        )
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(1024 * 1024 + 1)
    finally:
        os.close(fd)
    require(len(raw) <= 1024 * 1024 and sha(raw) == approved_hash, "Manifest bytes changed")
    return raw


class Authority:
    """Reopens the same exact bytes at every review boundary; never reloads authority."""

    def __init__(self, path, approved_hash, root, previous, requested, action, reference):
        self.path, self.approved_hash, self.root = Path(path), approved_hash, Path(root)
        self.args = (previous, requested, action, reference)
        self.original = private_bytes(path, approved_hash)
        self.plan, self.registry, self.unit = validate(self.original, approved_hash, root, *self.args)

    def recheck(self):
        raw = private_bytes(self.path, self.approved_hash)
        require(raw == self.original, "Manifest substituted at review boundary")
        plan, registry, unit = validate(raw, self.approved_hash, self.root, *self.args)
        require(plan == self.plan and unit == self.unit and registry == self.registry, "Authority/source changed")
        return plan

    def evidence(self):
        return {
            "manifest_sha256": self.approved_hash,
            "manifest_canonical_sha256": digest(self.plan),
            "action": self.args[2],
            "action_reference": self.args[3],
        }


def clean_environment(environment):
    require(
        set(environment) <= {"HOME", "PATH", "LC_ALL", "PYTHONDONTWRITEBYTECODE"},
        "Ambient environment/configuration override refused",
    )
    return dict(environment)
