"""W2.1 isolated OFFLINE adapter. No database/Docker/credential implementation.

Future connected integration requires separately reviewed source and authority.
All imports are inert stdlib/local pure functions. Never imports app or Alembic.
"""

from __future__ import annotations

import argparse
import ast
import difflib
import json
import os
import re
import stat
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from frozen_047 import BASELINE, representation, sha
from pg_lex import Refused

LOCK_SHA256 = "ea4307ed66a08da663b3826f9bdf34e3cc72849e610a5f8f70e105731ff1f632"
TARGET = {
    "target": "F",
    "host": "127.0.0.1",
    "hostaddr": "127.0.0.1",
    "port": 56043,
    "database": "uuid_w2_f_fresh",
    "user": "uuid_w2_f_bootstrap",
    "project": "sbom-uuid-w2-f",
    "service": "postgres_f",
    "volume": "sbom-uuid-w2-f_f_pgdata",
    "network": "sbom-uuid-w2-f_f_access",
    "postgresql": "16.15",
}
BUDGETS = {
    "attempts": 1,
    "simultaneous_connections": 1,
    "catalog_queries": 64,
    "transaction_controls": 4,
    "connect_seconds": 5,
    "statement_ms": 30000,
    "lock_ms": 1000,
    "idle_transaction_ms": 30000,
    "cooperative_unit_seconds": 120,
}
CONNECTION_CONTRACT = {
    "host": "127.0.0.1",
    "hostaddr": "127.0.0.1",
    "port": 56043,
    "dbname": "uuid_w2_f_fresh",
    "user": "uuid_w2_f_bootstrap",
    "passfile": "/dev/null",
    "sslmode": "disable",
    "gssencmode": "disable",
    "connect_timeout": 5,
    "application_name": "sbom_w21_f_bootstrap",
    "autocommit": False,
    "options": "-c default_transaction_read_only=on -c statement_timeout=30000 -c lock_timeout=1000 -c idle_in_transaction_session_timeout=30000 -c search_path=pg_catalog -c row_security=on",
}
ATTESTATIONS = (
    "source_reviewed",
    "target_reviewed",
    "credential_reviewed",
    "roles_reviewed",
    "network_egress_reviewed",
)
ACTIONS = ("bootstrap_validate", "bootstrap_install_047", "bootstrap_readback")
FORBIDDEN_CLUSTER = "7697252084555804711"
MARKER_CREATE = "CREATE TABLE public.alembic_version (version_num VARCHAR(128) NOT NULL PRIMARY KEY)"
MARKER_INSERT = "INSERT INTO public.alembic_version (version_num) VALUES (%s) RETURNING version_num"
SERIALIZATION_KEY = 7160085085


def require(ok, reason):
    if not ok:
        raise Refused(reason)


def canonical(value):
    return sha(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def unique_json(blob):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate JSON key")
            result[key] = value
        return result

    return json.loads(
        blob, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(Refused("Nonfinite JSON"))
    )


def private_manifest(path, approved_sha256):
    """Future review-file reader, never a password reader; tests use temp JSON."""
    require(
        isinstance(approved_sha256, str) and re.fullmatch(r"[0-9a-f]{64}", approved_sha256),
        "Exact operator-approved manifest byte hash required",
    )
    path = Path(path)
    require(
        path.is_absolute() and path.suffix == ".json" and ".." not in path.parts, "Private absolute JSON path required"
    )
    for part in (path, *path.parents):
        require(not part.is_symlink(), "Symlink review path refused")
    parent = path.parent.stat()
    require(parent.st_uid == os.getuid() and stat.S_IMODE(parent.st_mode) == 0o700, "Private review directory required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o600,
            "Private regular single-link manifest required",
        )
        require(info.st_size <= 1024 * 1024, "Review file too large")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(1024 * 1024 + 1)
    finally:
        os.close(fd)
    require(len(raw) <= 1024 * 1024 and sha(raw) == approved_sha256, "Approved manifest bytes changed")
    return raw, unique_json(raw)


def verify_sources(root):
    """AST/hash only; all historical bytes must match the immutable lock."""
    root = Path(root)
    lock = root / "infra/uuid-migration/fresh-bootstrap/source-lock.json"
    require(not lock.is_symlink() and sha(lock.read_bytes()) == LOCK_SHA256, "Source-lock bytes changed")
    pins = unique_json(lock.read_bytes())
    for relative, expected in pins.items():
        path = root / relative
        require(not path.is_symlink() and sha(path.read_bytes()) == expected, "Historical source pin mismatch")
    for folder in ("alembic/versions", "infra/uuid-migration/staged-alembic"):
        require(
            {str(p.relative_to(root)) for p in (root / folder).glob("*.py")}
            == {p for p in pins if p.startswith(folder + "/")},
            "Migration source set changed",
        )
    declarations = []
    for name in sorted(pins):
        if name.startswith(("alembic/versions/", "infra/uuid-migration/staged-alembic/")):
            tree = ast.parse((root / name).read_bytes())
            values = {}
            for node in tree.body:
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id in {
                            "revision",
                            "down_revision",
                            "branch_labels",
                            "depends_on",
                            "_TABLE",
                        }:
                            values[target.id] = ast.literal_eval(node.value)
            values["path"] = name
            declarations.append(values)
    graph = {row["revision"]: row for row in declarations}
    require(len(graph) == 85 and len(declarations) == 85, "Expected79 active and six staged")
    ordered, current = [], "085_uuid_sbom_component_expand"
    while current is not None:
        require(current in graph and current not in ordered, "Missing/cyclic migration parent")
        ordered.append(current)
        row = graph[current]
        require(row.get("branch_labels") is None and row.get("depends_on") is None, "Unexpected graph dependency")
        current = row["down_revision"]
    require(len(ordered) == 85, "Disconnected migration graph")
    ordered.reverse()
    require(ordered[46] == BASELINE and ordered[78] == "079_lifecycle_provider_verification", "Baseline/head changed")
    tables = [graph[revision].get("_TABLE") for revision in ordered[79:]]
    require(
        tables == ["tenants", "projects", "products", "logical_sbom", "sbom_source", "sbom_component"],
        "UUID scope/order changed",
    )
    return pins, [graph[revision] for revision in ordered]


def isolated_dependencies(root, graph):
    """No importing migrations: only048/064 need two frozen seed modules.

    A future engine can bind these frozen constants to reviewed modules without
    importing app.db/settings. This output is an inert dependency recipe, not
    a module loader or permission to run historical upgrade functions.
    """
    found = {}
    for row in graph[47:]:
        tree = ast.parse((Path(root) / row["path"]).read_bytes())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("app"):
                require(
                    node.module in {"app.authorization_catalog_seed_v1", "app.authorization_catalog_seed_v2"},
                    "Unreviewed application import",
                )
                found[row["revision"]] = node.module
            if isinstance(node, ast.Import):
                require(
                    not any(item.name.startswith("app") for item in node.names), "Application runtime import refused"
                )
    seeds, constants, alternatives = {}, {}, {}
    for module in found.values():
        text = (Path(root) / (module.replace(".", "/") + ".py")).read_text()
        tree = ast.parse(text)
        constants[module] = seed_constants(tree)
        seeds[module] = {"sha256": sha(text.encode()), "source": text, "constant_names": sorted(constants[module])}
    for row in graph[47:]:
        if row["revision"] not in found:
            continue
        original = (Path(root) / row["path"]).read_text()
        tree = ast.parse(original)
        body = []
        for node in tree.body:
            if isinstance(node, ast.ImportFrom) and node.module in constants:
                for alias in node.names:
                    require(alias.name in constants[node.module], "Unresolved frozen seed constant")
                    expression = seed_expression(constants[node.module][alias.name])
                    body.append(
                        ast.Assign(targets=[ast.Name(id=alias.asname or alias.name, ctx=ast.Store())], value=expression)
                    )
            else:
                body.append(node)
        tree.body = body
        proposed = ast.unparse(ast.fix_missing_locations(tree)) + "\n"
        # This is a review artifact only. No compile/exec/import of migrations.
        diff = "".join(
            difflib.unified_diff(
                original.splitlines(True),
                proposed.splitlines(True),
                fromfile=row["path"],
                tofile="isolated/" + Path(row["path"]).name,
            )
        )
        alternatives[row["revision"]] = {
            "source": proposed,
            "sha256": sha(proposed.encode()),
            "diff": diff,
            "diff_sha256": sha(diff.encode()),
            "executed": False,
        }
    return {
        "migration_bindings": found,
        "frozen_seeds": seeds,
        "source_representations": alternatives,
        "runtime_loader_implemented": False,
    }


def seed_constants(tree):
    """Evaluate only frozen literal containers and frozenset(literal), no exec."""
    values = {}

    def literal(node):
        if isinstance(node, ast.Name):
            require(node.id in values, "Unknown frozen seed name")
            return values[node.id]
        if isinstance(node, ast.Call):
            require(
                isinstance(node.func, ast.Name)
                and node.func.id == "frozenset"
                and len(node.args) == 1
                and not node.keywords,
                "Unreviewed seed expression",
            )
            return frozenset(literal(node.args[0]))
        if isinstance(node, ast.Dict):
            return {literal(k): literal(v) for k, v in zip(node.keys, node.values, strict=True)}
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return {ast.Tuple: tuple, ast.List: list, ast.Set: set}[type(node)](literal(n) for n in node.elts)
        return ast.literal_eval(node)

    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            continue
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            continue
        require(
            isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name),
            "Frozen seed must contain constants only",
        )
        name = node.targets[0].id
        require(name not in values, "Repeated seed constant")
        values[name] = literal(node.value)
    return values


def seed_expression(value):
    """Stable AST preserving dict insertion order and unordered-set semantics."""
    if isinstance(value, dict):
        return ast.Dict(keys=[seed_expression(k) for k in value], values=[seed_expression(v) for v in value.values()])
    if isinstance(value, frozenset):
        return ast.Call(
            func=ast.Name(id="frozenset", ctx=ast.Load()),
            args=[ast.Tuple(elts=[seed_expression(v) for v in sorted(value, key=repr)], ctx=ast.Load())],
            keywords=[],
        )
    if isinstance(value, (tuple, list, set)):
        items = sorted(value, key=repr) if isinstance(value, set) else value
        cls = {tuple: ast.Tuple, list: ast.List, set: ast.Set}[type(value)]
        fields = {"elts": [seed_expression(v) for v in items]}
        if cls is not ast.Set:
            fields["ctx"] = ast.Load()
        return cls(**fields)
    require(value is None or type(value) in {str, int, bool}, "Unsupported frozen literal")
    return ast.Constant(value=value)


def schedule(graph):
    units = [
        {
            "previous": None,
            "next": BASELINE,
            "kind": "frozen_047",
            "source": "scripts/schema/postgresql_047_baseline.sql",
        }
    ]
    units += [
        {
            "previous": row["down_revision"],
            "next": row["revision"],
            "kind": "historical" if i < 79 else "uuid_expand",
            "source": row["path"],
        }
        for i, row in enumerate(graph)
        if i >= 47
    ]
    for unit in units:
        unit.update(
            {
                "owned_transactions": 1,
                "new_process": True,
                "write_close_before_readback": True,
                "independent_readback_approval": True,
                "automatic_retry": False,
                "transaction_advisory_key": SERIALIZATION_KEY,
                "freshness_recheck_under_lock": True,
            }
        )
    return units


def next_unit(units, current, requested):
    require(isinstance(requested, str) and requested not in {"head", "heads"}, "One explicit next unit required")
    matched = [unit for unit in units if unit["previous"] == current and unit["next"] == requested]
    require(len(matched) == 1, "Skipped, repeated or out-of-order unit")
    return matched[0]


def reference_contract(root, pins):
    """Derive source-frozen reference expectations without running any seed."""

    def read(relative):
        raw = (Path(root) / relative).read_bytes()
        require(sha(raw) == pins[relative], "Reference dependency changed")
        return ast.parse(raw)

    def constant(relative, name):
        tree = read(relative)
        matches = [
            n.value
            for n in tree.body
            if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)
        ]
        require(len(matches) == 1, "Frozen migration constant missing")
        return ast.literal_eval(matches[0])

    v1 = seed_constants(read("app/authorization_catalog_seed_v1.py"))
    v2 = seed_constants(read("app/authorization_catalog_seed_v2.py"))
    permissions = {role: set(codes) for role, codes in v1["ROLE_PERMISSIONS_V1"].items()}
    permissions["PLATFORM_ADMIN"] = set(v2["PLATFORM_ADMIN_PERMISSIONS_V2"])
    permissions["TENANT_ADMIN"].update(
        constant("alembic/versions/065_scoped_configuration.py", "TENANT_CONFIG_PERMISSIONS")
    )
    permissions["PLATFORM_ADMIN"].update(
        constant("alembic/versions/066_platform_configuration_permissions.py", "PERMISSIONS")
    )
    for relative in [
        "alembic/versions/067_component_advisor_foundation.py",
        "alembic/versions/068_component_advisor_policies.py",
    ]:
        for role, codes in constant(relative, "ROLE_PERMISSIONS").items():
            permissions[role].update(codes)
    permissions["PLATFORM_ADMIN"].update(constant("alembic/versions/075_platform_advisor_policies.py", "PERMISSIONS"))
    return {
        "after048": {
            "roles": v1["ROLE_SCOPES_V1"],
            "permissions": list(v1["ALL_PERMISSIONS_V1"]),
            "role_permissions": {role: list(codes) for role, codes in v1["ROLE_PERMISSIONS_V1"].items()},
            "seed_audit_action": "AUTHORIZATION_CATALOG_SEEDED",
        },
        "after079": {
            "role_permissions": {role: sorted(codes) for role, codes in permissions.items()},
            "role_versions": {
                "PLATFORM_ADMIN": 4,
                "TENANT_ADMIN": 4,
                "SECURITY_ANALYST": 3,
                "DEVELOPER": 2,
                "VIEWER": 2,
            },
        },
        "acceptance": [
            "exact role scopes/status/system/assignability",
            "exact mappings and protected grants per frozen source",
            "seed audit evidence exists",
            "no users/tenants/memberships automatically created",
            "no legacy business rows",
            "provider defaults and CycloneDX/SPDX initialization separately authorized after final constraints",
            "Native reservation/activation/outbox enrollment separately authorized, never default password/admin",
        ],
        "executed": False,
    }


def validate_manifest(raw, approved_hash, action, approval, sources, now=None):
    """Pure future authority validation; does not enable this build's live CLI."""
    require(
        isinstance(approved_hash, str) and re.fullmatch(r"[0-9a-f]{64}", approved_hash) and sha(raw) == approved_hash,
        "Operator-approved raw manifest hash required",
    )
    plan = unique_json(raw)
    require(isinstance(plan, dict) and plan.get("schema") == "w21-f-bootstrap-v1", "Wrong manifest schema")
    fields = {
        "schema",
        "target",
        "accepted",
        "unit",
        "identity",
        "source_sha256",
        "budgets",
        *ATTESTATIONS,
        "integrity_approvals",
        "integrity_attestations",
        "approvals",
        "expires_at",
        "effective_authentication_independently_reviewed",
        "effective_authentication_review_reference",
        "resources",
        "fresh_metadata",
        "expected_047_catalog_sha256",
        "connection_contract",
    }
    require(set(plan) == fields, "Missing or unknown approval field")
    require(plan.get("target") == TARGET, "Only explicit F target permitted")
    require(
        plan.get("accepted") is False and plan.get("unit") == {"previous": None, "next": BASELINE},
        "Only uninstalled047 unit permitted",
    )
    identity = plan.get("identity", {})
    require(set(identity) == {"system_identifier", "database_oid", "server_ip"}, "Unknown identity field")
    require(
        isinstance(identity.get("system_identifier"), str)
        and re.fullmatch(r"[1-9][0-9]{0,19}", identity["system_identifier"])
        and identity["system_identifier"] != FORBIDDEN_CLUSTER,
        "New verified F cluster required",
    )
    require(
        type(identity.get("database_oid")) is int and identity["database_oid"] > 0,
        "Exact positive F database OID required",
    )
    require(
        isinstance(identity.get("server_ip"), str)
        and re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", identity["server_ip"]),
        "Observed F internal address required",
    )
    require(plan.get("source_sha256") == sources and plan.get("budgets") == BUDGETS, "Source/budget mismatch")
    require(all(type(v) is int for v in plan["budgets"].values()), "Exact integer budgets required")
    require(plan.get("connection_contract") == CONNECTION_CONTRACT, "Connection options changed")
    require(all(plan.get(key) is True for key in ATTESTATIONS), "Operator attestations pending")
    require(
        plan.get("integrity_approvals") == {} and plan.get("integrity_attestations") == [False] * 7,
        "Integrity testing not authorized",
    )
    require(
        all(value is False for value in plan["integrity_attestations"]), "Exact false integrity attestations required"
    )
    require(
        action in ACTIONS and isinstance(approval, str) and bool(approval.strip()), "Action-specific approval required"
    )
    approvals = plan.get("approvals")
    require(
        isinstance(approvals, dict) and set(approvals) <= set(ACTIONS) and approvals.get(action) == approval,
        "Missing/incorrect action approval",
    )
    require(len(set(approvals.values())) == len(approvals), "Action references must be distinct")
    try:
        expires = datetime.fromisoformat(plan["expires_at"])
    except (ValueError, TypeError, KeyError):
        raise Refused("Aware UTC expiry required") from None
    require(
        expires.utcoffset() is not None
        and expires.utcoffset().total_seconds() == 0
        and expires > (now or datetime.now(UTC)),
        "Expired or non-UTC approval",
    )
    require(plan.get("effective_authentication_independently_reviewed") is True, "Authentication evidence pending")
    require(
        isinstance(plan.get("effective_authentication_review_reference"), str)
        and bool(plan["effective_authentication_review_reference"].strip()),
        "Independent effective-auth review reference required",
    )
    resources = plan.get("resources", {})
    require(
        set(resources)
        == {
            "daemon_id",
            "socket",
            "container_id",
            "image_id",
            "volume_identity",
            "network_id",
            "credential_metadata_reference",
        },
        "Unexpected resource field",
    )
    for key in (
        "daemon_id",
        "container_id",
        "image_id",
        "volume_identity",
        "network_id",
        "credential_metadata_reference",
    ):
        require(
            isinstance(resources.get(key), str) and bool(resources[key].strip()),
            "Actual approved resource/provenance pin required",
        )
    require(
        resources["daemon_id"] == "1f8c7fe5-5972-4adc-8d6e-363a38572be1"
        and resources.get("socket") == "/Users/ferozebasha/.docker/run/docker.sock",
        "Only separately verified local Desktop daemon/socket allowed",
    )
    require(
        all(re.fullmatch(r"[0-9a-f]{64}", resources[k]) for k in ("container_id", "network_id", "volume_identity")),
        "Exact new resource identity hashes required",
    )
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", resources["image_id"]) is not None, "Pinned local image required")
    require(
        plan.get("fresh_metadata") is not None and plan.get("expected_047_catalog_sha256") is not None,
        "Reviewed fresh/post047 semantic catalogs required",
    )
    require(re.fullmatch(r"[0-9a-f]{64}", plan["expected_047_catalog_sha256"]) is not None, "Post047 hash invalid")
    return plan


def recheck_manifest(path, approved_sha256, original, **kwargs):
    raw, _ = private_manifest(path, approved_sha256)
    require(raw == original, "Manifest changed before authentication")
    return validate_manifest(raw, approved_sha256, **kwargs)


def clean_environment(environment):
    require(
        not any(
            k.startswith("PG") or k in {"DATABASE_URL", "PYTHONPATH", "DOCKER_HOST", "DOCKER_CONTEXT"}
            for k in environment
        ),
        "Ambient target/configuration override refused",
    )
    require(
        set(environment) <= {"HOME", "PATH", "LC_ALL", "PYTHONDONTWRITEBYTECODE"},
        "Explicit clean subprocess environment required",
    )
    return dict(environment)


def safe_error(error, secret=""):
    """Retain only class/SQLSTATE; never format driver arguments/DSNs."""
    name = type(error).__name__
    state = getattr(error, "sqlstate", None)
    return {
        "exception": name if re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]{0,80}", name) else "Error",
        "sqlstate": state if isinstance(state, str) and re.fullmatch(r"[A-Z0-9]{5}", state) else None,
        "reason": "REDACTED_OPERATOR_REVIEW_REQUIRED",
    }


@dataclass
class Budget:
    """Cooperative deadline, never a hard network/COMMIT wall-clock claim."""

    started: float
    queries: int = 0
    controls: int = 0
    attempts: int = 0

    def operation(self, kind, now=None):
        require(
            (time.monotonic() if now is None else now) - self.started < 120,
            "Cooperative deadline exhausted; cleanup still required",
        )
        require(kind in {"query", "control", "connect"}, "Unreviewed operation")
        field, limit = {"query": ("queries", 64), "control": ("controls", 4), "connect": ("attempts", 1)}[kind]
        require(getattr(self, field) < limit, "Operation budget exhausted")
        setattr(self, field, getattr(self, field) + 1)


@dataclass
class UnitContract:
    """Pure receipt state machine for mocked future transaction ownership.

    No connect/execute/commit implementation is present. A caller cannot obtain
    an ACCEPTED outcome from precommit/marker receipts alone. Receipts are not
    evidence of real PostgreSQL behavior and are never exposed as live success.
    """

    statement_hashes: tuple[str, ...]
    expected_catalog: str
    phase: str = "NEW"
    installed: int = 0
    physically_closed: bool = False
    serialization_verified: bool = False

    def begin(self, *, freshness_verified, separately_authorized):
        require(
            self.phase == "NEW" and freshness_verified and separately_authorized,
            "Freshness/authority required before BEGIN",
        )
        self.phase = "INSTALLING"
        return "BEGIN READ WRITE"

    def lock_ack(self, key, *, freshness_rechecked):
        require(
            self.phase == "INSTALLING"
            and not self.serialization_verified
            and key == SERIALIZATION_KEY
            and freshness_rechecked is True,
            "Reviewed transaction lock and fresh catalog recheck required",
        )
        self.serialization_verified = True

    def schema_ack(self, statement_hash):
        require(
            self.phase == "INSTALLING" and self.serialization_verified and self.installed < len(self.statement_hashes),
            "Unexpected schema acknowledgment",
        )
        require(statement_hash == self.statement_hashes[self.installed], "Schema statement/order mismatch")
        self.installed += 1

    def marker_instruction(self):
        require(
            self.phase == "INSTALLING" and self.installed == len(self.statement_hashes) and self.installed > 0,
            "Marker forbidden before complete schema installation",
        )
        self.phase = "MARKER_PENDING"
        return {"create": MARKER_CREATE, "insert": MARKER_INSERT, "parameters": (BASELINE,)}

    def marker_ack(self, rowcount, rows, *, schema_verified):
        require(
            self.phase == "MARKER_PENDING"
            and type(rowcount) is int
            and rowcount == 1
            and rows == [(BASELINE,)]
            and schema_verified,
            "Marker/schema acknowledgment mismatch",
        )
        self.phase = "PRECOMMIT"

    def commit_requested(self):
        require(self.phase == "PRECOMMIT", "Cannot commit an incomplete unit")
        self.phase = "COMMIT_PENDING"

    def commit_ack(self):
        require(self.phase == "COMMIT_PENDING", "Unexpected COMMIT acknowledgment")
        self.phase = "COMMITTED_NOT_VERIFIED"

    def failure(self):
        require(
            self.phase
            not in {
                "VERIFIED",
                "ROLLED_BACK",
                "UNKNOWN_COMMIT_STOP",
                "FAILED_BEFORE_BEGIN",
                "ROLLBACK_UNCONFIRMED_STOP",
            },
            "Terminal state; no retry",
        )
        if self.phase == "NEW":
            self.phase = "FAILED_BEFORE_BEGIN"
            return "STOP_NO_TRANSACTION"
        if self.phase == "ROLLBACK_PENDING":
            self.phase = "ROLLBACK_UNCONFIRMED_STOP"
            return "STOP_MANUAL_RECONCILIATION"
        if self.phase == "COMMIT_PENDING":
            self.phase = "UNKNOWN_COMMIT_STOP"
            return "STOP_MANUAL_RECONCILIATION"
        if self.phase == "COMMITTED_NOT_VERIFIED":
            return "STOP_COMMITTED_NOT_VERIFIED"
        self.phase = "ROLLBACK_PENDING"
        return "ROLLBACK"

    def rollback_ack(self):
        require(self.phase == "ROLLBACK_PENDING", "Rollback cannot prove an unknown COMMIT")
        self.phase = "ROLLED_BACK"

    def close_ack(self, physically_closed):
        require(physically_closed is True and not self.physically_closed, "Physical close must be explicit and unique")
        self.physically_closed = True

    def readback(self, marker, catalog_hash, *, separate_authorization, new_readonly_connection_closed):
        require(
            self.phase == "COMMITTED_NOT_VERIFIED" and self.physically_closed,
            "Write close/acknowledged commit required",
        )
        require(
            separate_authorization
            and new_readonly_connection_closed
            and marker == [BASELINE]
            and catalog_hash == self.expected_catalog,
            "Independent committed-state read-back failed",
        )
        self.phase = "VERIFIED"
        return {"mock_contract_verified": True, "runtime_accepted": False}


def inspect_offline(root):
    pins, graph = verify_sources(root)
    proposed = representation((Path(root) / "scripts/schema/postgresql_047_baseline.sql").read_bytes())
    folder = Path(root) / "infra/uuid-migration/fresh-bootstrap"
    for name, expected in [
        ("047-execution.proposed.sql", proposed["execution_sql"]),
        ("047-transformation.diff", proposed["diff"]),
    ]:
        path = folder / name
        require(
            not path.is_symlink() and path.read_bytes() == expected.encode(), "Saved execution proposal/diff mismatch"
        )
    return {
        "active_head": graph[78]["revision"],
        "combined_head": graph[-1]["revision"],
        "source_sha256": pins,
        "baseline": proposed,
        "units": schedule(graph),
        "dependencies": isolated_dependencies(root, graph),
        "reference_contract": reference_contract(root, pins),
        "final_constraints": "NOT IMPLEMENTED; separately reviewed stage after085",
        "live_available": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("offline", "live"), required=True)
    args = parser.parse_args(argv)
    if args.mode == "live":
        parser.error(
            "W2.1 build refuses all connected operations; independent source review and future integration required"
        )
    root = Path(__file__).resolve().parents[3]
    result = inspect_offline(root)
    print(
        json.dumps(
            {
                "status": "OFFLINE_ONLY",
                "active_head": result["active_head"],
                "combined_head": result["combined_head"],
                "units": len(result["units"]),
                "baseline_sha256": result["baseline"]["execution_sha256"],
                "connections": 0,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
