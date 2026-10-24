"""Future F authority/resource/credential adapters. Import performs no IO.

All resource/file/secret readers are injected. There is no command runner or
credential reader wired to a CLI. A manifest never constitutes observed proof.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import stat
from datetime import UTC, datetime
from pathlib import Path

from reviewed import load

F_SECRET = "/Users/ferozebasha/.sbom-uuid-w2-f/postgres-password"
FIELDS = {
    "schema",
    "accepted",
    "w23_manifest",
    "activation_sources",
    "dependency_sources",
    "sql_allowlist",
    "connection",
    "approvals",
    "expires_at",
    "integrity_attestations",
    "integrity_approvals",
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def source_bundle(root):
    folder = Path(root) / "infra/uuid-migration/f-activation"
    require(all(not p.is_symlink() for p in (folder, *folder.parents)), "Symlink activation directory")
    require(all(not p.is_symlink() for p in folder.iterdir()), "Symlink activation source")
    return {
        str(p.relative_to(root)): sha(p.read_bytes())
        for p in sorted(folder.iterdir())
        if p.is_file() and p.suffix in {".py", ".json", ".yml", ".md"}
    }


def verify_dependencies(pins):
    """Exact installed distribution files, reviewed separately; no import needed.

    The future operator must pin all installed .py files in these three compiler/
    driver distributions, not just self-reported version strings.
    """
    from importlib.metadata import distribution

    require(set(pins) == {"SQLAlchemy", "alembic", "psycopg"}, "Missing dependency approval")
    for name, reviewed in pins.items():
        dist = distribution(name)
        files = {
            str(f): sha(Path(dist.locate_file(f)).read_bytes())
            for f in dist.files
            if str(f).endswith((".py", ".so", ".dylib"))
        }
        require(reviewed == {"version": dist.version, "files": files}, "Installed dependency drift")


class Authority:
    """Bind exact original bytes of wrapper AND original W2.3 unit manifest."""

    def __init__(self, root, path, expected, previous, requested, action, reference):
        require(isinstance(expected, str) and re.fullmatch("[0-9a-f]{64}", expected), "Approved byte hash missing")
        self.root, self.path, self.expected = Path(root), path, expected
        self.modules, self.registry = load(root)
        a, s = self.modules["authority"], self.modules["source_registry"]
        self.raw = a.private_bytes(path, expected)
        require(sha(self.raw) == expected, "Activation manifest byte mismatch")
        self.plan = s.unique_json(self.raw)
        self.args = (previous, requested, action, reference)
        self.validate()
        nested = self.plan["w23_manifest"]
        self.unit_authority = a.Authority(
            nested["path"], nested["sha256"], root, previous, requested, action, reference
        )
        self.recheck()

    def validate(self):
        p = self.plan
        require(
            set(p) == FIELDS and p["schema"] == "w24a-activation-review-v1" and p["accepted"] is False,
            "Unreviewed activation manifest",
        )
        require(p["activation_sources"] == source_bundle(self.root), "Activation source drift")
        verify_dependencies(p["dependency_sources"])
        expiry = datetime.fromisoformat(p["expires_at"])
        require(
            expiry.utcoffset() is not None and expiry.utcoffset().total_seconds() == 0 and expiry > datetime.now(UTC),
            "Expired activation review",
        )
        previous, requested, action, reference = self.args
        require(
            action in {"unit_validate", "unit_execute", "unit_readback"}
            and reference
            and p["approvals"].get(action) == reference
            and len(set(p["approvals"].values())) == len(p["approvals"])
            and set(p["approvals"]) <= {"unit_validate", "unit_execute", "unit_readback"},
            "Action approval missing",
        )
        require(
            p["integrity_attestations"] == [False] * 7
            and all(v is False for v in p["integrity_attestations"])
            and p["integrity_approvals"] == {},
            "Integrity testing not authorized",
        )
        require(set(p["w23_manifest"]) == {"path", "sha256"}, "Original unit authority required")
        allow = p["sql_allowlist"]
        require(
            set(allow) == {"catalog_queries", "migration_statements", "session_statements", "marker_statements"}
            and all(
                isinstance(v, list) and all(isinstance(h, str) and re.fullmatch("[0-9a-f]{64}", h) for h in v)
                for v in allow.values()
            ),
            "Reviewed driver SQL allowlist required",
        )

    def recheck(self):
        a = self.modules["authority"]
        raw = a.private_bytes(self.path, self.expected)
        require(raw == self.raw and sha(raw) == self.expected, "Original activation manifest changed")
        require(
            self.modules["source_registry"].unique_json(raw) == self.plan,
            "In-memory manifest differs from approved bytes",
        )
        self.validate()
        self.unit_authority.recheck()
        from transport import connection_options

        require(self.plan["connection"] == connection_options(self), "Unapproved transport connection options")
        require(
            datetime.fromisoformat(self.plan["expires_at"])
            <= datetime.fromisoformat(self.unit_authority.plan["expires_at"]),
            "Activation cannot renew unit expiry",
        )
        return self.unit_authority.plan

    def evidence(self):
        return {
            "manifest_sha256": self.expected,
            "manifest_canonical_sha256": self.modules["source_registry"].digest(self.plan),
        }


def clean_environment(environment):
    require(
        set(environment) <= {"HOME", "PATH", "LC_ALL", "PYTHONDONTWRITEBYTECODE"},
        "Worker environment must be explicitly clean",
    )
    require(
        not any(
            k.startswith("PG")
            or k
            in {"DATABASE_URL", "PYTHONPATH", "DOCKER_HOST", "DOCKER_CONTEXT", "COMPOSE_FILE", "COMPOSE_PROJECT_NAME"}
            for k in environment
        ),
        "Ambient target configuration refused",
    )
    return {k: environment[k] for k in ("HOME", "PATH", "LC_ALL", "PYTHONDONTWRITEBYTECODE") if k in environment}


def file_metadata(path, *, lstat=os.lstat):
    """Future safe stat contract. Tests inject stat; no caller here reads a secret."""
    path = Path(path)
    require(str(path) == F_SECRET and not any(p == ".." for p in path.parts), "Wrong credential source")
    chain = [lstat(p) for p in (path, *path.parents)]
    require(all(not stat.S_ISLNK(s.st_mode) for s in chain), "Symlink secret path")
    s, parent = chain[:2]
    require(
        stat.S_ISREG(s.st_mode)
        and s.st_nlink == 1
        and s.st_uid == os.getuid()
        and stat.S_IMODE(s.st_mode) == 0o600
        and stat.S_IMODE(parent.st_mode) == 0o700
        and parent.st_uid == os.getuid(),
        "Private credential identity mismatch",
    )
    return {
        "path": str(path),
        "uid": s.st_uid,
        "inode": s.st_ino,
        "size": s.st_size,
        "mode": 0o600,
        "parent_mode": 0o700,
        "nlink": 1,
        "mtime_ns": s.st_mtime_ns,
        "ctime_ns": s.st_ctime_ns,
    }


def correlate_secret(plan, raw, provider):
    """Correlate already stat-verified bytes in memory; never hash/log/cache them.

    Provider.read_host must use O_NOFOLLOW/fstat-before-and-after matching the
    full metadata; read_mounted must bound output and use the pinned container.
    Both return mutable bytearrays; caller receives only the host bytearray for
    the single connection and must erase it. Python/driver internal copies cannot
    be guaranteed erased and are never persisted by this adapter.
    """
    c, r = plan["credential_metadata"], plan["resources"]
    require(
        c["path"] == F_SECRET and raw["credential"] == {"regular": True, "symlink": False, "metadata": c},
        "Unverified host provenance",
    )
    mount = raw["mount"]
    source = mount["source"]
    require(
        raw["desktop"] is True
        and raw["platform"] == "Docker Desktop"
        and r["socket"] == "/Users/ferozebasha/.docker/run/docker.sock"
        and r["daemon_id"] == "1f8c7fe5-5972-4adc-8d6e-363a38572be1",
        "Unreviewed local Desktop context",
    )
    require(
        mount == {"type": "bind", "source": source, "destination": "/run/secrets/f_password", "rw": False}
        and source in (F_SECRET, "/host_mnt" + F_SECRET)
        and raw["secret_mount_count"] == 1,
        "Unreviewed secret mount",
    )
    host = mounted = None
    try:
        host = provider.read_host(F_SECRET, c)
        mounted = provider.read_mounted(r["container_id"], "/run/secrets/f_password", 4096)
        require(
            isinstance(host, bytearray)
            and isinstance(mounted, bytearray)
            and 20 <= len(host) <= 4096
            and len(host) == c["size"]
            and hmac.compare_digest(host, mounted),
            "Secret correlation failed",
        )
        require(provider.stat_host(F_SECRET) == c, "Credential changed while read")
        return host
    except BaseException:
        if isinstance(host, bytearray):
            host[:] = b"\0" * len(host)
        raise
    finally:
        if isinstance(mounted, bytearray):
            mounted[:] = b"\0" * len(mounted)


def observe_resources(authority, provider):
    """Provider is an explicit local metadata adapter, never an ambient CLI.

    Raw normalized W2.3 shape plus platform/mount cardinality/settings evidence.
    No Docker implementation is activated by this package.
    """
    plan = authority.recheck()
    raw = provider.resources(plan["resources"]["socket"], plan["resources"]["container_id"])
    require(
        raw["settings"]
        == {
            "running": True,
            "restart_count": 0,
            "nano_cpus": 1000000000,
            "memory": 536870912,
            "shm_size": 67108864,
            "pids_limit": 128,
            "restart_policy": "no",
            "network_internal": False,
            "icc": "false",
        },
        "F limits/startup/network drift",
    )
    trimmed = {k: v for k, v in raw.items() if k not in {"desktop", "platform", "secret_mount_count", "settings"}}
    # Do not trust a provider assertion that it correlated a secret. Create that
    # evidence only after the actual injected byte readers returned equal bytes.
    trimmed["correlation"] = {
        "performed": True,
        "equal": True,
        "container_id": plan["resources"]["container_id"],
        "source": F_SECRET,
        "destination": "/run/secrets/f_password",
    }
    authority.modules["observations"].verify_resources(plan, trimmed)
    secret = correlate_secret(plan, raw, provider)
    try:
        authority.recheck()
    except BaseException:
        secret[:] = b"\0" * len(secret)
        raise
    return secret, authority.modules["source_registry"].digest(trimmed)


def authentication_evidence(*, connected, hba_rows, independently_reviewed):
    require(all(r.get("error") is None for r in hba_rows), "HBA file parse error")
    return {
        "connection_authenticated": connected,
        "hba_file_parse": "PASS",
        "effective_password_rule": "REVIEWED" if independently_reviewed else "UNKNOWN",
        "limitation": "HBA file contents do not prove last-loaded rules; supplying a password does not prove it was required",
    }
