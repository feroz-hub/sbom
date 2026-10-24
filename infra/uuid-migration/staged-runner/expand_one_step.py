"""Staged isolated one-revision integration. --mode offline never connects.

No normal Alembic env/config discovery. Connected modes need separate approval.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import stat
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

import uuid_w1_common as common
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.script.revision import Revision, RevisionMap
from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool

BASE = "079_lifecycle_provider_verification"
COMMON_SHA256 = "4b9ef6c1708ae8385db39c618aec10eba35e3b8e972b6de7c5a2583a6eabad94"
SOURCES = (
    ("080_uuid_public_id_expand", "tenants", "2fc6e6f9992d0763ddf6818b9e7b62d573eef2b7cda01a39689b8fffcbc623f8"),
    ("081_uuid_projects_expand", "projects", "28f803f5c5c439f1ae0f0fdb0748368b244c2c31b060bb1a61ff6302a3d2d95e"),
    ("082_uuid_products_expand", "products", "76d830f79e699cbdd5116c1e848cc5923f10281a764a17f0abd6c1cf8c4b5ace"),
    (
        "083_uuid_logical_sbom_expand",
        "logical_sbom",
        "d7f8dbe4c262f4a045572c173b7fd61e38d003fa87f9ec28093427161234495e",
    ),
    ("084_uuid_sbom_source_expand", "sbom_source", "13a84b0d6d3201a64be7ba90a32560a5c5738a319be1fc8af29d2364aec49803"),
    (
        "085_uuid_sbom_component_expand",
        "sbom_component",
        "45f331390609e52ceddbf0968651b5ec817bf26811f6f67845d1fb6d99cdbb0f",
    ),
)
CHAIN = (BASE, *(s[0] for s in SOURCES))
_USED = False


def require(condition, message):
    common.require(condition, message)


def declarations(source):
    tree = ast.parse(source)
    names = {"revision", "down_revision", "branch_labels", "depends_on", "_TABLE"}
    return {
        n.targets[0].id: ast.literal_eval(n.value)
        for n in tree.body
        if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name) and n.targets[0].id in names
    }


def discover(root=common.ROOT):
    """Read/AST/hash only; retain bytes so later import cannot race a changed file."""
    require(
        hashlib.sha256(Path(common.__file__).read_bytes()).hexdigest() == COMMON_SHA256,
        "Reviewed W1.6B safety dependency changed",
    )
    folder = root / "infra/uuid-migration/staged-alembic"
    require({p.name for p in folder.glob("*.py")} == {s[0] + ".py" for s in SOURCES}, "Staged source set mismatch")
    evidence = (root / "docs/uuid-migration/phase2/10-w1-expand-transaction-refactor.md").read_text()
    blobs = {}
    previous = BASE
    for revision, table, expected in SOURCES:
        path = folder / (revision + ".py")
        require(path.is_file() and not path.is_symlink(), "Staged source missing or symlinked")
        data = path.read_bytes()
        require(
            hashlib.sha256(data).hexdigest() == expected and expected in evidence,
            "Staged source/evidence hash mismatch",
        )
        c = declarations(data)
        require(
            c
            == {
                "revision": revision,
                "down_revision": previous,
                "branch_labels": None,
                "depends_on": None,
                "_TABLE": table,
            },
            "Staged declaration mismatch",
        )
        blobs[revision] = data
        previous = revision
    active = []
    for path in sorted((root / "alembic/versions").glob("*.py")):
        c = declarations(path.read_bytes())
        if "revision" in c:
            active.append(c)
    require(len(active) == 79 and len({c["revision"] for c in active}) == 79, "Active graph changed; review required")
    graph = RevisionMap(
        lambda: iter(
            Revision(
                c["revision"],
                c["down_revision"],
                dependencies=c.get("depends_on"),
                branch_labels=c.get("branch_labels"),
            )
            for c in active
        )
    )
    require(graph.heads == (BASE,), "Active graph no longer ends at approved 079")
    require(len(list(graph.iterate_revisions(BASE, "base"))) == 79, "Active ancestry changed")
    # Synthetic boundary node represents already-applied 079, never its code.
    isolated = RevisionMap(
        lambda: iter([Revision(BASE, None), *(Revision(r, CHAIN[i]) for i, (r, _, _) in enumerate(SOURCES))])
    )
    require(isolated.heads == (CHAIN[-1],), "Isolated graph invalid")
    return blobs


def next_only(current, requested):
    require(isinstance(current, str) and current in CHAIN, "Unknown current marker")
    require(
        isinstance(requested, str) and requested in CHAIN[1:], "Exactly one explicit approved next revision required"
    )
    position = CHAIN.index(current)
    require(position < 6 and CHAIN[position + 1] == requested, "Skipped/out-of-order/already-applied request")
    return position


def validate_manifest(plan, mode, approval, requested):
    """Pure checks, no files, credentials, Docker or connections."""
    require(mode in ("validate", "execute"), "Connected mode invalid")
    for key in (
        "disposable",
        "accepted",
        "baseline_reviewed",
        "writers_and_privileges_reviewed",
        "exclusive_ddl_window_reviewed",
        "disposable_secret_provenance_reviewed",
        "old_monolith_excluded",
    ):
        require(plan.get(key) is True, "Required D approval/old-monolith exclusion missing")
    require(
        plan.get("target") == "D"
        and plan.get("host") == "127.0.0.1"
        and type(plan.get("port")) is int
        and plan["port"] == 56041,
        "Only approved D endpoint allowed",
    )
    require(
        plan.get("database") == "uuid_w1_d_rehearsal" and plan.get("user") == "uuid_w1_d_bootstrap",
        "Only D identities allowed",
    )
    require(
        plan.get("password_file") == str(Path.home() / ".sbom-uuid-w1-disposable-20261016/postgres-password"),
        "Dedicated D secret required",
    )
    require(plan.get("docker_socket") == str(Path.home() / ".docker/run/docker.sock"), "Local Desktop socket required")
    require(
        plan.get("docker_binary") == "/Applications/Docker.app/Contents/Resources/bin/docker",
        "Local Desktop CLI required",
    )
    for key in ("schema_sha256", "container_sha256", "volume_sha256", "docker_binary_sha256", "container_id"):
        require(
            isinstance(plan.get(key), str) and re.fullmatch("[0-9a-f]{64}", plan[key]), "Reviewed identity hash missing"
        )
    require(type(plan.get("database_oid")) is int and plan["database_oid"] > 0, "Database OID missing")
    require(
        isinstance(plan.get("system_identifier"), str) and plan["system_identifier"].isdigit(),
        "Cluster identity missing",
    )
    require(
        isinstance(plan.get("network_ids"), dict) and bool(plan["network_ids"]), "Dedicated network identity missing"
    )
    require(
        all(
            isinstance(n, str)
            and n.startswith("sbom-uuid-w1_")
            and isinstance(v, str)
            and re.fullmatch("[0-9a-f]{64}", v)
            for n, v in plan["network_ids"].items()
        ),
        "Dedicated network identity invalid",
    )
    for key in ("daemon_id", "server_address", "postmaster_started_at", "prefix_review_reference"):
        require(isinstance(plan.get(key), str) and bool(plan[key]), "Independent prefix/identity review missing")
    expiry = datetime.fromisoformat(plan["expires_utc"])
    require(expiry.tzinfo is not None and expiry > datetime.now(UTC), "Approval expired or timezone missing")
    approvals = plan.get("approvals", {})
    key = "expand_execute" if mode == "execute" else "expand_validate"
    require(
        isinstance(approval, str) and bool(approval) and approvals.get(key) == approval,
        "Target-specific action approval missing",
    )
    refs = list(approvals.values())
    require(
        all(isinstance(v, str) and v for v in refs) and len(refs) == len(set(refs)),
        "Approvals must be distinct nonempty references",
    )
    require(plan.get("next_revision") == requested, "Approval does not cover requested revision")
    next_only(plan.get("current_revision"), requested)
    require(not any(k.startswith("PG") for k in os.environ), "Remove inherited libpq overrides")


class Evidence:
    """Private counts/metadata only; do not inherit W1.6B's fixed 085 start event."""

    def __init__(self, path, plan):
        path = Path(path)
        require(
            path.is_absolute() and not path.resolve().is_relative_to(common.ROOT),
            "Private evidence outside checkout required",
        )
        p = path.parent.lstat()
        require(
            not path.parent.is_symlink() and p.st_uid == os.getuid() and stat.S_IMODE(p.st_mode) == 0o700,
            "Private evidence parent required",
        )
        self.stream = os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "w")
        try:
            self.emit(
                "start",
                plan_sha256=common.digest(plan),
                current=plan["current_revision"],
                next=plan["next_revision"],
                container_id=plan["container_id"],
                system_identifier=plan["system_identifier"],
            )
        except BaseException:
            self.stream.close()
            raise

    def emit(self, event, **fields):
        self.stream.write(
            json.dumps({"utc": datetime.now(UTC).isoformat(), "event": event, **fields}, sort_keys=True) + "\n"
        )
        self.stream.flush()
        os.fsync(self.stream.fileno())

    def close(self):
        self.stream.close()


def identity(raw, plan):
    row = common.query(raw, common.IDENTITY_SQL).fetchone()
    expected = (
        plan["database"],
        plan["user"],
        plan["user"],
        plan["database_oid"],
        plan["system_identifier"],
        16,
        plan["server_address"],
        5432,
        plan["postmaster_started_at"],
        False,
        "origin",
    )
    require(row == expected, "D identity/session changed")


def snapshot(raw):
    # Unlike index phase, exclude NO relation/index from expand comparison.
    return {name: common.query(raw, sql, {"index_names": []}).fetchall() for name, sql in common.CATALOG_SQL.items()}


def marker(raw):
    rows = common.query(raw, "SELECT version_num FROM public.alembic_version").fetchall()
    require(len(rows) == 1 and rows[0][0] in CHAIN, "Marker missing/multiple/unrecognized; manual reconciliation")
    return rows[0][0]


def prefix(raw, current):
    """Exact committed prefix, no ahead-of-marker adoption (including old 080)."""
    count = CHAIN.index(current)
    guards = common.query(raw, common.GUARD_SQL).fetchall()
    if not count:
        require(not guards, "Unexpected pre-080 shared guard")
    else:
        require(
            len(guards) == 1
            and guards[0][:12]
            == (0, "f", True, "plpgsql", "v", False, ["search_path=pg_catalog"], False, False, False, "u", True)
            and hashlib.sha256(guards[0][12].encode()).hexdigest() == common.GUARD_BODY_SHA256,
            "Changed shared identity guard",
        )
    require(
        not common.query(raw, "SELECT 1 FROM pg_catalog.pg_event_trigger WHERE evtenabled <> 'D' LIMIT 1").fetchone(),
        "Enabled event trigger forbidden",
    )
    for i, (_, table, _) in enumerate(SOURCES):
        relation = common.query(
            raw,
            "SELECT c.oid,c.relkind,c.relpersistence,c.relrowsecurity,c.relforcerowsecurity FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=:table",
            {"table": table},
        ).fetchall()
        require(len(relation) == 1 and relation[0][1:] == ("r", "p", False, False), "Target table shape/RLS mismatch")
        oid = relation[0][0]
        cols = common.query(
            raw,
            "SELECT attnum FROM pg_catalog.pg_attribute WHERE attrelid=:oid AND attname='public_id' AND NOT attisdropped",
            {"oid": oid},
        ).fetchall()
        checks = common.query(
            raw,
            "SELECT contype,convalidated,pg_catalog.pg_get_expr(conbin,conrelid) FROM pg_catalog.pg_constraint WHERE conrelid=:oid AND conname=:name",
            {"oid": oid, "name": f"ck_{table}_public_id_v4"},
        ).fetchall()
        triggers = common.query(raw, common.TRIGGERS_SQL, {"oid": oid}).fetchall()
        require(
            not common.query(
                raw, "SELECT 1 FROM pg_catalog.pg_rewrite WHERE ev_class=:oid AND ev_type<>'1' LIMIT 1", {"oid": oid}
            ).fetchone(),
            "Unapproved write rule",
        )
        if i >= count:
            require(not cols and not checks and not triggers, "Objects ahead of marker or legacy monolith; stop")
            continue
        rows = common.query(raw, common.TABLE_SQL, {"table": table}).fetchall()
        require(len(rows) == 1, "Expanded definition missing")
        r = rows[0]
        require(
            r[6:10] == (True, False, "", "")
            and r[10] in ("gen_random_uuid()", "pg_catalog.gen_random_uuid()")
            and all(r[12:18]),
            "Expanded column/PK/role mismatch",
        )
        require(len(checks) == 1 and checks[0][:2] == ("c", False), "Expected unvalidated UUID CHECK missing")
        normalized = re.sub(r'[\s()"]', "", checks[0][2]).replace("pg_catalog.", "").replace("::text", "")
        require(normalized == f"public_idISNULLORpublic_id~'{common.PATTERN}'", "UUID CHECK expression mismatch")
        expected = [
            (
                f"trg_{table}_public_id_immutable",
                17,
                "O",
                0,
                "uuid_public_identity_guard_v1",
                "public",
                f"CREATE TRIGGER trg_{table}_public_id_immutable AFTER UPDATE ON public.{table} FOR EACH ROW WHEN ((old.public_id IS DISTINCT FROM new.public_id)) EXECUTE FUNCTION public.uuid_public_identity_guard_v1()",
                "",
                0,
            ),
            (
                f"trg_{table}_public_id_insert",
                7,
                "O",
                0,
                "uuid_public_identity_guard_v1",
                "public",
                f"CREATE TRIGGER trg_{table}_public_id_insert BEFORE INSERT ON public.{table} FOR EACH ROW EXECUTE FUNCTION public.uuid_public_identity_guard_v1()",
                "",
                0,
            ),
        ]
        require(triggers == expected, "Prefix trigger definition mismatch")


def verify(raw, plan, current, pre_hash=True):
    require(datetime.fromisoformat(plan["expires_utc"]) > datetime.now(UTC), "Approval expired during invocation")
    common.verify_docker(plan)
    identity(raw, plan)
    require(marker(raw) == current, "Marker/schema mismatch; no automatic continuation")
    prefix(raw, current)
    state = snapshot(raw)
    if pre_hash:
        require(common.digest(state) == plan["schema_sha256"], "Approved prefix catalog/ACL snapshot mismatch")
    return state


def delta(before, after, table, first):
    """Only one new UUID column/check/two triggers (+ first shared function)."""
    relation = [r for r in before["relations"] if r[1] == table]
    require(len(relation) == 1, "Delta target relation missing")
    oid = relation[0][0]
    for section in before:
        old = before[section]
        new = after[section]
        if section not in ("columns", "constraints", "triggers", "functions"):
            require(old == new, "Unrelated catalog delta; rollback/manual review")
            continue
        added = [r for r in new if r not in old]
        require(all(r in new for r in old), "Existing catalog object modified; rollback/manual review")
        if section == "columns":
            require(len(added) == 1 and added[0][0] == oid and added[0][2] == "public_id", "Unexpected column delta")
        elif section == "constraints":
            require(
                len(added) == 1 and added[0][1:4] == (oid, f"ck_{table}_public_id_v4", "c"),
                "Unexpected constraint delta",
            )
        elif section == "triggers":
            require(len(added) == 2 and all(r[1] == oid for r in added), "Unexpected trigger delta")
        else:
            require(
                len(added) == int(first) and (not first or added[0][1] == "uuid_public_identity_guard_v1"),
                "Unexpected function delta",
            )


def module_from_verified_blob(revision, blob):
    module = ModuleType("isolated_" + revision)
    exec(compile(blob, revision + ".py", "exec"), module.__dict__)
    return module


def apply_revision(connection, revision, blob, current):
    """Future only: explicit Operations context; never run normal env or stamp."""
    config = Config()  # No filename, script_location, URL or environment script.
    config.attributes["isolated_revision"] = revision
    context = MigrationContext.configure(
        connection,
        opts={
            "transactional_ddl": True,
            "as_sql": False,
            "transaction_per_migration": True,
            "version_table_schema": "public",
        },
    )
    require(
        not context.as_sql and context.impl.transactional_ddl and connection.in_transaction(),
        "Real transactional PostgreSQL DDL required",
    )
    require(
        connection.dialect.name == "postgresql" and connection.connection.driver_connection.autocommit is False,
        "Transactional PG driver required",
    )
    module = module_from_verified_blob(revision, blob)
    with Operations.context(context):
        module.upgrade()  # Exactly one hash-pinned staged function, no graph traversal.
    result = connection.execute(
        text("UPDATE public.alembic_version SET version_num=:next WHERE version_num=:current"),
        {"next": revision, "current": current},
    )
    require(result.rowcount == 1, "Conditional revision marker change failed")


def outcome(phase):
    return {
        "preflight": "NO_MIGRATION_ATTEMPT",
        "transaction": "ROLLBACK_REQUIRES_CONFIRMATION",
        "commit_pending": "UNKNOWN_COMMIT_STOP",
        "committed": "COMMITTED_NOT_VERIFIED",
        "verified": "COMMITTED_AND_VERIFIED",
    }.get(phase, "STOP_RECONCILE")


def execute_step(plan, requested, blob, evidence, *, engine_factory=None, checker=verify, applier=apply_revision):
    """Lifecycle boundary with injectable fake engine/checker for offline tests."""
    global _USED
    require(not _USED, "One invocation/process may attempt only one revision")
    _USED = True
    index = next_only(plan["current_revision"], requested)
    phase = "preflight"
    engine = None
    before = None

    def creator():
        raw = common.connect(plan)
        try:
            # Identity before SQLAlchemy dialect initialization or READ WRITE.
            identity(raw, plan)
            raw.autocommit = False
            raw.read_only = False
            return raw
        except BaseException:
            raw.close()
            raise

    try:
        common.verify_docker(plan)
        engine = (
            engine_factory
            or (
                lambda: create_engine(
                    "postgresql+psycopg://", creator=creator, poolclass=NullPool, echo=False, hide_parameters=True
                )
            )
        )()
        with engine.connect() as connection:
            require(not connection.in_transaction(), "External transaction forbidden")
            with connection.begin():
                phase = "transaction"
                raw = connection.connection.driver_connection
                common.acquire_operator_lock(raw)
                # Marker lock prevents another cooperating migration from advancing it.
                connection.execute(text("LOCK TABLE ONLY public.alembic_version IN EXCLUSIVE MODE NOWAIT"))
                before = checker(raw, plan, plan["current_revision"])
                applier(connection, requested, blob, plan["current_revision"])
                after = checker(raw, plan, requested, False)
                delta(before, after, SOURCES[index][1], index == 0)
                evidence.emit("precommit", current=plan["current_revision"], next=requested)
                phase = "commit_pending"
            phase = "committed"
            evidence.emit("commit_acknowledged", revision=requested)
        # NullPool closes first physical connection before independent verification.
        engine.dispose()
        engine = None
        with common.connect(plan) as raw:
            after = checker(raw, plan, requested, False)
            delta(before, after, SOURCES[index][1], index == 0)
        phase = "verified"
        evidence.emit("committed_verified_closed", revision=requested, catalog_sha256=common.digest(after))
    except BaseException:
        try:
            evidence.emit("stopped", classification=outcome(phase))
        except OSError:
            pass
        raise
    finally:
        if engine is not None:
            engine.dispose()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("offline", "validate", "execute"), default="offline")
    parser.add_argument("--next-revision")
    parser.add_argument("--plan")
    parser.add_argument("--approval-id")
    parser.add_argument("--evidence")
    args = parser.parse_args(argv)
    evidence = None
    try:
        blobs = discover()
        if args.mode == "offline":
            require(
                not any((args.plan, args.approval_id, args.evidence, args.next_revision)),
                "Offline mode accepts no runtime inputs",
            )
            print("PASS: approved source hashes and isolated 079–085 graph; no runtime action")
            return 0
        require(
            all((args.plan, args.approval_id, args.evidence, args.next_revision)), "Explicit runtime inputs required"
        )
        plan = json.loads(common.private_file(args.plan))
        validate_manifest(plan, args.mode, args.approval_id, args.next_revision)
        evidence = Evidence(args.evidence, plan)
        if args.mode == "validate":
            common.verify_docker(plan)
            with common.connect(plan) as raw:
                verify(raw, plan, plan["current_revision"])
            evidence.emit("connected_validation_only_closed")
        else:
            execute_step(plan, args.next_revision, blobs[args.next_revision], evidence)
        return 0
    except (Exception, KeyboardInterrupt) as error:
        # Alembic/SQLAlchemy exceptions can include SQL/params/credentials: never stringify.
        message = (
            str(error)
            if isinstance(error, common.SafetyStop)
            else "STOP: reconcile private evidence/target state; no automatic retry"
        )
        print(message)
        return 2
    finally:
        if evidence is not None:
            try:
                evidence.close()
            except OSError:
                print("STOP: evidence close failed; reconcile outcome before continuation")
                return 2


if __name__ == "__main__":
    raise SystemExit(main())
