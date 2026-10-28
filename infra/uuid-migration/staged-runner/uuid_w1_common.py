"""Staged D-only safety gates. Importing this module performs no I/O.

Future validation still requires explicit read-only target authorization.
No application/config-loader imports; no connection or Docker call at import.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import time
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

import psycopg
from psycopg.pq import TransactionStatus
from sqlalchemy import text
from sqlalchemy.dialects import postgresql

TABLES = ("tenants", "projects", "products", "logical_sbom", "sbom_source", "sbom_component")
REVISION = "085_uuid_sbom_component_expand"
PATTERN = "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
GUARD_BODY_SHA256 = "ff93761fa4dd31fa6dff7c25f3aedf41bc960e181a234d390f540e359d2e8d58"
ROOT = Path(__file__).resolve().parents[3]
LOCK_KEY = 7160085085
_BATCH_DEADLINE = ContextVar("uuid_w1_batch_deadline", default=None)
SQLSTATE_REASONS = {
    "23505": "Uniqueness violation; reconcile index/batch, retain committed mappings; no automatic retry",
    "40P01": "Deadlock; stop and reconcile current unit before separately permitted restart",
    "55P03": "Lock unavailable or timed out; stop, preserve completed units; do not skip locked rows",
    "57014": "Statement canceled; reconcile unit and any incomplete concurrent index",
    "08006": "Connection lost; commit/index outcome may be unknown; manual reconciliation required",
    "08003": "Connection unavailable; current unit outcome requires reconciliation",
}


class SafetyStop(Exception):
    """Messages must contain only fixed diagnostics, never driver error text."""


def require(condition, message):
    if not condition:
        raise SafetyStop(message)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str, separators=(",", ":")).encode()).hexdigest()


def private_file(path):
    """Open a user-owned regular 0600 file using O_NOFOLLOW; pin fstat.

    Require its immediate directory to be private, outside the checkout.
    Read contents only at future invocation, never during static verification.
    """
    path = Path(path)
    require(path.is_absolute() and not path.is_symlink(), "Private path must be absolute and non-symlink")
    resolved = path.resolve(strict=True)
    require(not resolved.is_relative_to(ROOT), "Private files must be outside checkout")
    parent = path.parent.lstat()
    require(not path.parent.is_symlink(), "Private parent must not be a symlink")
    require(parent.st_uid == os.getuid() and stat.S_IMODE(parent.st_mode) == 0o700, "Private parent must be owned 0700")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1,
            "Private file identity mismatch",
        )
        require(
            stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 1048576, "Private file must be nonempty 0600"
        )
        return stream.read()


def arguments(action):
    parser = argparse.ArgumentParser(description=f"STAGED D-only {action}; validation also needs authorization")
    parser.add_argument("--plan", required=True, help="Absolute private operator-reviewed JSON plan")
    parser.add_argument("--approval-id", required=True, help="Nonsecret reference matching this action's approval")
    parser.add_argument("--evidence", required=True, help="New absolute private JSONL path outside checkout")
    parser.add_argument("--mode", choices=("validate", "execute"), default="validate")
    if action == "backfill":
        parser.add_argument("--batch-size", type=int, default=500)
        parser.add_argument("--max-batches", type=int, default=10000)
        parser.add_argument("--max-seconds", type=int, default=3600)
        parser.add_argument("--gap-sweeps", type=int, default=3)
    return parser.parse_args()


def load_plan(args, action):
    plan = json.loads(private_file(args.plan))
    require(plan["target"] == "D" and plan["disposable"] is True and plan["accepted"] is True, "D acceptance missing")
    require(plan["baseline_and_expand_reviewed"] is True, "B-shaped baseline and expanded schema review missing")
    require(plan["writers_and_privileges_reviewed"] is True, "Writer/trigger/role review missing")
    require(plan["exclusive_ddl_window_reviewed"] is True, "Single-operator/no-unrelated-DDL window required")
    require(plan["disposable_secret_provenance_reviewed"] is True, "Dedicated disposable secret provenance required")
    require(
        Path(plan["password_file"]) == Path.home() / ".sbom-uuid-w1-disposable-20261016/postgres-password",
        "Only the existing dedicated D secret is allowed",
    )
    require(plan["host"] == "127.0.0.1" and plan["port"] == 56041, "Only reviewed D loopback endpoint is allowed")
    require(
        plan["database"] == "uuid_w1_d_rehearsal" and plan["user"] == "uuid_w1_d_bootstrap", "D-only names required"
    )
    key = action if args.mode == "execute" else "validate"
    require(
        bool(args.approval_id) and plan["approvals"].get(key) == args.approval_id, "Separate action approval missing"
    )
    expires = datetime.fromisoformat(plan["expires_utc"])
    require(expires.tzinfo is not None and expires > datetime.now(UTC), "Approval expired or timezone missing")
    approvals = [v for v in plan["approvals"].values() if v]
    require(len(approvals) == len(set(approvals)), "Actions require distinct approval references")
    require(plan["revision"] == REVISION, "Approved revision must be expanded 085")
    for key in ("schema_sha256", "container_sha256", "volume_sha256", "docker_binary_sha256"):
        require(bool(re.fullmatch("[0-9a-f]{64}", plan[key])), "Expected evidence hash missing")
    require(bool(re.fullmatch("[0-9a-f]{64}", plan["container_id"])), "Full D container identity required")
    require(plan["system_identifier"].isdigit() and plan["database_oid"] > 0, "Cluster/database identity required")
    require(
        plan["network_ids"] and all(n.startswith("sbom-uuid-w1_") for n in plan["network_ids"]),
        "D-only networks required",
    )
    require(set(plan["accepted_index_oids"]) <= set(TABLES), "Unknown accepted index table")
    require(all(type(v) is int and v > 0 for v in plan["accepted_index_oids"].values()), "Invalid approved index OID")
    require(1000 <= plan["index_statement_ms"] <= 3600000, "Explicit bounded index timeout required")
    require(not any(key.startswith("PG") for key in os.environ), "Remove libpq environment overrides before invocation")
    return plan


class Evidence:
    def __init__(self, path, plan, action, mode):
        path = Path(path)
        require(path.is_absolute() and not path.resolve().is_relative_to(ROOT), "Evidence must be outside checkout")
        parent = path.parent.lstat()
        require(not path.parent.is_symlink() and parent.st_uid == os.getuid(), "Evidence parent identity mismatch")
        require(stat.S_IMODE(parent.st_mode) == 0o700, "Evidence directory must be private 0700")
        self.stream = os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "w")
        self.emit(
            "start",
            action=action,
            mode=mode,
            plan_sha256=digest(plan),
            container_id=plan["container_id"],
            system_identifier=plan["system_identifier"],
            revision=REVISION,
            source_sha256={
                p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(Path(__file__).parent.glob("*.py"))
            },
        )

    def emit(self, event, **fields):
        # Callers pass only counts, metadata and fixed diagnostics; never row IDs/UUIDs.
        record = {"utc": datetime.now(UTC).isoformat(), "event": event, **fields}
        self.stream.write(json.dumps(record, sort_keys=True) + "\n")
        self.stream.flush()
        os.fsync(self.stream.fileno())

    def close(self):
        self.stream.close()


def docker(plan, *args):
    endpoint = Path(plan["docker_socket"])
    expected = Path.home() / ".docker/run/docker.sock"
    require(endpoint.is_absolute() and endpoint == expected, "Only the reviewed local Desktop Unix socket is allowed")
    info = endpoint.stat()
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid(), "Local Desktop socket identity mismatch")
    binary = Path(plan["docker_binary"])
    require(binary.is_absolute() and binary.is_file(), "Explicit Docker CLI required")
    require(
        binary.resolve() == Path("/Applications/Docker.app/Contents/Resources/bin/docker").resolve(),
        "Reviewed Docker Desktop CLI required",
    )
    require(hashlib.sha256(binary.read_bytes()).hexdigest() == plan["docker_binary_sha256"], "Docker CLI changed")
    result = subprocess.run(
        [str(binary), "--host", "unix://" + str(endpoint), *args],
        capture_output=True,
        timeout=10,
        check=False,
        env={"HOME": str(Path.home()), "PATH": "/usr/bin:/bin"},
    )
    require(result.returncode == 0, "Local Docker metadata inspection failed")
    return result.stdout.decode().strip()


def verify_docker(plan):
    daemon_fmt = '{"id":{{json .ID}},"os":{{json .OperatingSystem}},"type":{{json .OSType}}}'
    daemon = json.loads(docker(plan, "info", "--format", daemon_fmt))
    require(
        daemon["id"] == plan["daemon_id"] and daemon["type"] == "linux" and "docker desktop" in daemon["os"].lower(),
        "Local Docker Desktop daemon mismatch",
    )
    fmt = (
        '{"id":{{json .Id}},"image":{{json .Image}},"created":{{json .Created}},'
        '"started":{{json .State.StartedAt}},"running":{{json .State.Running}},'
        '"restarts":{{json .RestartCount}},"mounts":{{json .Mounts}},'
        '"ports":{{json .NetworkSettings.Ports}},"networks":{{json .NetworkSettings.Networks}},'
        '"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
        '"service":{{json (index .Config.Labels "com.docker.compose.service")}}}'
    )
    state = json.loads(docker(plan, "container", "inspect", "--format", fmt, plan["container_id"]))
    require(state["id"] == plan["container_id"] and state["running"], "D container identity/running state changed")
    require(state["project"] == "sbom-uuid-w1" and state["service"] == "postgres_d", "D Compose identity mismatch")
    require(state["ports"] == {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "56041"}]}, "D publication mismatch")
    require({n: v["NetworkID"] for n, v in state["networks"].items()} == plan["network_ids"], "D network changed")
    data = [m for m in state["mounts"] if m["Destination"] == "/var/lib/postgresql/data"]
    require(
        len(data) == 1 and data[0]["Type"] == "volume" and data[0]["Name"] == "sbom-uuid-w1_d_pgdata",
        "D storage mismatch",
    )
    require(digest(state) == plan["container_sha256"], "Reviewed D metadata changed")
    volume_fmt = '{"name":{{json .Name}},"driver":{{json .Driver}},"created":{{json .CreatedAt}},"mountpoint":{{json .Mountpoint}}}'
    volume = json.loads(docker(plan, "volume", "inspect", "--format", volume_fmt, "sbom-uuid-w1_d_pgdata"))
    require(digest(volume) == plan["volume_sha256"], "D volume identity changed")
    attached = docker(
        plan,
        "container",
        "ls",
        "--all",
        "--no-trunc",
        "--filter",
        "volume=sbom-uuid-w1_d_pgdata",
        "--format",
        "{{.ID}}",
    )
    require(attached.splitlines() == [plan["container_id"]], "D storage is not exclusively attached")
    for name, network_id in plan["network_ids"].items():
        endpoints = json.loads(docker(plan, "network", "inspect", "--format", "{{json .Containers}}", network_id))
        require(set(endpoints) == {plan["container_id"]}, "D network has unexpected attachments")
        require(name.startswith("sbom-uuid-w1_"), "Shared network forbidden")


@lru_cache(maxsize=128)
def compiled(sql):
    statement = text(sql).compile(dialect=postgresql.dialect(paramstyle="pyformat"))
    return str(statement), tuple(statement.params)


def query(conn, sql, params=None):
    deadline = _BATCH_DEADLINE.get()
    if deadline is not None:
        remaining = int((deadline - time.monotonic()) * 1000)
        require(remaining > 0, "Batch time budget exhausted; current transaction must roll back")
        conn.execute("SELECT pg_catalog.set_config('statement_timeout', %s, true)", (str(min(remaining, 10000)),))
    statement, keys = compiled(sql)
    return conn.execute(statement, {key: params[key] for key in keys} if keys else None)


@contextmanager
def bounded_transaction(conn):
    require(
        conn.autocommit and conn.info.transaction_status == TransactionStatus.IDLE,
        "Batch requires idle autocommit connection",
    )
    token = _BATCH_DEADLINE.set(time.monotonic() + 20)
    try:
        with conn.transaction():
            query(conn, "SELECT pg_catalog.set_config('lock_timeout','1000',true)")
            yield
            require(time.monotonic() < _BATCH_DEADLINE.get(), "Batch exceeded time budget before commit")
    finally:
        _BATCH_DEADLINE.reset(token)


def connect(plan):
    # Explicit kwargs; no URL, service file, dotenv, app.db or launcher fallback.
    password = private_file(plan["password_file"]).decode().rstrip("\r\n")
    require(bool(password) and "\x00" not in password and "\n" not in password, "Invalid disposable secret file")
    return psycopg.connect(
        host="127.0.0.1",
        hostaddr="127.0.0.1",
        port=56041,
        dbname="uuid_w1_d_rehearsal",
        user="uuid_w1_d_bootstrap",
        password=password,
        passfile="/dev/null",
        sslmode="disable",
        gssencmode="disable",
        connect_timeout=5,
        application_name="uuid_w1_staged_runner",
        autocommit=True,
        options="-c search_path=pg_catalog -c default_transaction_read_only=on "
        "-c statement_timeout=10000 -c lock_timeout=1000 "
        "-c idle_in_transaction_session_timeout=15000 -c row_security=on",
    )


IDENTITY_SQL = """
SELECT pg_catalog.current_database(), CURRENT_USER, SESSION_USER, d.oid,
       c.system_identifier::pg_catalog.text,
       pg_catalog.current_setting('server_version_num')::pg_catalog.int4 / 10000,
       pg_catalog.inet_server_addr()::pg_catalog.text, pg_catalog.inet_server_port(),
       pg_catalog.pg_postmaster_start_time()::pg_catalog.text,
       pg_catalog.pg_is_in_recovery(), pg_catalog.current_setting('session_replication_role')
FROM pg_catalog.pg_database AS d CROSS JOIN pg_catalog.pg_control_system() AS c
WHERE d.datname = pg_catalog.current_database()
"""

# Stable catalog/ACL snapshot, excluding only the six independently checked new indexes.
# No business records, sequence positions, statistics or other changing data are read.
CATALOG_SQL = {
    "relations": """SELECT c.oid, c.relname, c.relkind, c.relpersistence, c.relowner, c.relacl::text,
        c.relrowsecurity, c.relforcerowsecurity FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'
        AND NOT (c.relname = ANY(:index_names)) ORDER BY c.oid""",
    "columns": """SELECT a.attrelid,a.attnum,a.attname,a.atttypid,a.atttypmod,a.attnotnull,
        a.attidentity,a.attgenerated,a.attacl::text,pg_catalog.pg_get_expr(d.adbin,d.adrelid)
        FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid
        JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
        WHERE n.nspname='public' AND a.attnum>0 AND NOT a.attisdropped
        AND NOT (c.relname = ANY(:index_names)) ORDER BY a.attrelid,a.attnum""",
    "constraints": """SELECT c.oid,c.conrelid,c.conname,c.contype,c.convalidated,
        pg_catalog.pg_get_constraintdef(c.oid,true) FROM pg_catalog.pg_constraint c
        JOIN pg_catalog.pg_namespace n ON n.oid=c.connamespace
        WHERE n.nspname='public' ORDER BY c.oid""",
    "indexes": """SELECT i.indexrelid,i.indrelid,i.indisvalid,i.indisready,i.indislive,
        pg_catalog.pg_get_indexdef(i.indexrelid) FROM pg_catalog.pg_index i
        JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid
        JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND NOT (c.relname = ANY(:index_names)) ORDER BY i.indexrelid""",
    "triggers": """SELECT t.oid,t.tgrelid,t.tgfoid,t.tgenabled,pg_catalog.pg_get_triggerdef(t.oid,true)
        FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid
        JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY t.oid""",
    "functions": """SELECT p.oid,p.proname,p.proowner,p.proacl::text,p.prosrc,p.proconfig,
        p.prosecdef,p.provolatile,p.proisstrict,p.proparallel,p.proleakproof,p.prorettype,p.proargtypes::text
        FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='public' ORDER BY p.oid""",
    "rules": """SELECT r.oid,r.ev_class,pg_catalog.pg_get_ruledef(r.oid,true)
        FROM pg_catalog.pg_rewrite r JOIN pg_catalog.pg_class c ON c.oid=r.ev_class
        JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY r.oid""",
    "policies": """SELECT p.* FROM pg_catalog.pg_policy p ORDER BY p.oid""",
    "events": """SELECT e.* FROM pg_catalog.pg_event_trigger e ORDER BY e.oid""",
    "roles": """SELECT r.oid,r.rolname,r.rolsuper,r.rolinherit,r.rolcreaterole,r.rolcreatedb,
        r.rolcanlogin,r.rolreplication,r.rolbypassrls,r.rolconfig FROM pg_catalog.pg_roles r ORDER BY r.oid""",
    "members": """SELECT m.* FROM pg_catalog.pg_auth_members m ORDER BY m.oid""",
    "namespaces": """SELECT n.oid,n.nspname,n.nspowner,n.nspacl::text
        FROM pg_catalog.pg_namespace n WHERE n.nspname='public' ORDER BY n.oid""",
    "inherits": """SELECT i.* FROM pg_catalog.pg_inherits i ORDER BY i.inhrelid,i.inhseqno""",
}

TABLE_SQL = """
SELECT c.oid,c.relkind,c.relpersistence,c.relrowsecurity,c.relforcerowsecurity,
       a.attnum,a.atttypid='pg_catalog.uuid'::pg_catalog.regtype,a.attnotnull,
       a.attidentity,a.attgenerated,pg_catalog.pg_get_expr(d.adbin,d.adrelid),
       pk.attnum,pk.atttypid='pg_catalog.int4'::pg_catalog.regtype,pk.attnotnull,
       EXISTS(SELECT 1 FROM pg_catalog.pg_constraint x WHERE x.conrelid=c.oid
              AND x.contype='p' AND x.conkey=ARRAY[pk.attnum]::pg_catalog.int2[]),
       pg_catalog.has_table_privilege(c.oid,'SELECT'), pg_catalog.has_table_privilege(c.oid,'UPDATE'),
       pg_catalog.pg_has_role(c.relowner,'USAGE')
FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid AND a.attname='public_id' AND NOT a.attisdropped
JOIN pg_catalog.pg_attribute pk ON pk.attrelid=c.oid AND pk.attname='id' AND NOT pk.attisdropped
JOIN pg_catalog.pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
WHERE n.nspname='public' AND c.relname=:table
"""

TRIGGERS_SQL = """
SELECT t.tgname,t.tgtype,t.tgenabled,t.tgnargs,p.proname,n.nspname,
       pg_catalog.pg_get_triggerdef(t.oid,false),t.tgattr::text,t.tgconstraint
FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid
JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
WHERE t.tgrelid=:oid AND NOT t.tgisinternal ORDER BY t.tgname
"""

INDEX_SQL = """
SELECT c.oid,c.relkind,i.indrelid,am.amname,i.indisunique,i.indisvalid,i.indisready,
       i.indislive,i.indisprimary,i.indisexclusion,i.indnullsnotdistinct,i.indimmediate,
       i.indnkeyatts,i.indnatts,i.indkey::text,i.indoption::text,i.indcollation::text,
       i.indexprs IS NULL,i.indpred IS NULL,oc.opcname,onsp.nspname,
       EXISTS(SELECT 1 FROM pg_catalog.pg_constraint x WHERE x.conindid=c.oid),
       c.reloptions,c.relpersistence
FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
LEFT JOIN pg_catalog.pg_index i ON i.indexrelid=c.oid
LEFT JOIN pg_catalog.pg_am am ON am.oid=c.relam
LEFT JOIN pg_catalog.pg_opclass oc ON oc.oid=i.indclass[0]
LEFT JOIN pg_catalog.pg_namespace onsp ON onsp.oid=oc.opcnamespace
WHERE n.nspname='public' AND c.relname=:name
"""

GUARD_SQL = """
SELECT p.pronargs,p.prokind,p.prorettype='pg_catalog.trigger'::pg_catalog.regtype,l.lanname,
       p.provolatile,p.prosecdef,p.proconfig,p.proisstrict,p.proretset,p.proleakproof,p.proparallel,
       pg_catalog.has_function_privilege(CURRENT_USER,p.oid,'EXECUTE'),p.prosrc
FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
JOIN pg_catalog.pg_language l ON l.oid=p.prolang
WHERE n.nspname='public' AND p.proname='uuid_public_identity_guard_v1'
"""


def index_name(table):
    require(table in TABLES, "Table is not allowlisted")
    return f"uq_{table}_public_id"


def qualified(table):
    require(table in TABLES, "Table is not allowlisted")
    return f'"public"."{table}"'


def index_ddl(table):
    # PG disallows a schema-qualified CREATE INDEX name; ON fixes its namespace.
    return f'CREATE UNIQUE INDEX CONCURRENTLY "{index_name(table)}" ON {qualified(table)} USING btree ("public_id")'


def verify_identity(conn, plan):
    row = query(conn, IDENTITY_SQL).fetchone()
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
    require(row == expected, "D PostgreSQL identity/version/session state mismatch")
    require(
        query(conn, "SELECT version_num FROM public.alembic_version").fetchall() == [(REVISION,)],
        "Alembic revision mismatch",
    )


def verify_schema(conn, plan):
    require(
        query(
            conn,
            "SELECT pg_catalog.has_schema_privilege('public','USAGE'),pg_catalog.has_schema_privilege('public','CREATE')",
        ).fetchone()
        == (True, True),
        "Maintenance schema privileges missing",
    )
    snapshot = {
        name: query(conn, sql, {"index_names": [index_name(t) for t in TABLES]}).fetchall()
        for name, sql in CATALOG_SQL.items()
    }
    observed = digest(snapshot)
    require(observed == plan["schema_sha256"], "Approved catalog/ACL fingerprint mismatch")
    require(
        not query(conn, "SELECT 1 FROM pg_catalog.pg_event_trigger WHERE evtenabled <> 'D' LIMIT 1").fetchone(),
        "Enabled DDL event triggers require a separate side-effect design",
    )
    guards = query(conn, GUARD_SQL).fetchall()
    require(len(guards) == 1, "Shared guard missing or overloaded")
    require(
        guards[0][:12]
        == (0, "f", True, "plpgsql", "v", False, ["search_path=pg_catalog"], False, False, False, "u", True)
        and hashlib.sha256(guards[0][12].encode()).hexdigest() == GUARD_BODY_SHA256,
        "Shared identity guard definition mismatch",
    )
    result = {}
    for table in TABLES:
        rows = query(conn, TABLE_SQL, {"table": table}).fetchall()
        require(len(rows) == 1, "Expected expanded table definition missing")
        r = rows[0]
        require(
            r[1:5] == ("r", "p", False, False) and r[6:10] == (True, False, "", ""),
            "Expanded UUID/table definition mismatch",
        )
        require(r[10] in ("gen_random_uuid()", "pg_catalog.gen_random_uuid()"), "UUID default mismatch")
        require(all(r[12:18]), "Integer PK or maintenance SELECT/UPDATE/ownership permissions missing")
        triggers = query(conn, TRIGGERS_SQL, {"oid": r[0]}).fetchall()
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
        require(triggers == expected, "Identity triggers altered or additional user triggers need review")
        require(
            not query(
                conn, "SELECT 1 FROM pg_catalog.pg_rewrite WHERE ev_class=:oid AND ev_type<>'1' LIMIT 1", {"oid": r[0]}
            ).fetchone(),
            "Write rules need review",
        )
        require(
            query(
                conn,
                "SELECT 1 FROM pg_catalog.pg_constraint WHERE conrelid=:oid AND conname=:name",
                {"oid": r[0], "name": f"ck_{table}_public_id_v4"},
            ).fetchone(),
            "UUID v4 CHECK missing",
        )
        result[table] = (r[0], r[5])
    require(
        query(
            conn, "SELECT pg_catalog.has_function_privilege(CURRENT_USER,'pg_catalog.gen_random_uuid()','EXECUTE')"
        ).fetchone()
        == (True,),
        "Allocator permission missing",
    )
    return result


def verify_indexes(conn, plan, tables, *, require_all, created=None):
    known = {**plan["accepted_index_oids"], **(created or {})}
    result = {}
    for table in TABLES:
        name = index_name(table)
        require(
            not query(
                conn,
                "SELECT 1 FROM pg_catalog.pg_constraint c JOIN pg_catalog.pg_namespace n ON n.oid=c.connamespace WHERE n.nspname='public' AND c.conname=:name LIMIT 1",
                {"name": name},
            ).fetchone(),
            "Same-name constraint conflicts with staged index phase",
        )
        rows = query(conn, INDEX_SQL, {"name": name}).fetchall()
        others = query(
            conn,
            "SELECT indexrelid FROM pg_catalog.pg_index WHERE indrelid=:oid AND :attnum=ANY(indkey) AND indexrelid<>:index_oid",
            {"oid": tables[table][0], "attnum": tables[table][1], "index_oid": rows[0][0] if rows else 0},
        ).fetchall()
        require(not others, "Unexpected additional public_id index")
        if not rows:
            require(not require_all and table not in known, "Required or previously accepted unique index is missing")
            result[table] = None
            continue
        require(len(rows) == 1, "Index name is ambiguous")
        row = rows[0]
        expected = (
            "i",
            tables[table][0],
            "btree",
            True,
            True,
            True,
            True,
            False,
            False,
            False,
            True,
            1,
            1,
            str(tables[table][1]),
            "0",
            "0",
            True,
            True,
            "uuid_ops",
            "pg_catalog",
            False,
            None,
            "p",
        )
        require(row[1:] == expected, "Unique index invalid/incomplete or definition mismatch; manual review required")
        require(known.get(table) == row[0], "Existing valid index requires explicit reviewed OID; no silent adoption")
        result[table] = row[0]
    return result


def verify_all(conn, plan, *, require_all, created=None):
    require(
        datetime.fromisoformat(plan["expires_utc"]).astimezone(UTC) > datetime.now(UTC),
        "Approval expired",
    )
    verify_docker(plan)
    verify_identity(conn, plan)
    tables = verify_schema(conn, plan)
    indexes = verify_indexes(conn, plan, tables, require_all=require_all, created=created)
    return tables, indexes


def acquire_operator_lock(conn):
    require(
        query(conn, "SELECT pg_catalog.pg_try_advisory_lock(:key)", {"key": LOCK_KEY}).fetchone() == (True,),
        "Another cooperating UUID runner owns the D lock",
    )


def guarded_main(action, run):
    evidence = None
    try:
        args = arguments(action)
        plan = load_plan(args, action)
        evidence = Evidence(args.evidence, plan, action, args.mode)
        verify_docker(plan)  # Before opening a socket to PostgreSQL.
        with connect(plan) as conn:
            run(conn, plan, args, evidence)
        evidence.emit("finished")
        print("Staged operation completed; inspect private evidence. No schema acceptance implied.")
        return 0
    except (Exception, KeyboardInterrupt) as error:
        code = getattr(error, "sqlstate", None)
        # Never stringify a libpq/SQL/Docker exception: DETAIL can contain UUIDs/passwords.
        message = (
            str(error)
            if isinstance(error, SafetyStop)
            else SQLSTATE_REASONS.get(code, "Stopped; reconcile private target/catalog state before continuation")
        )
        if evidence is not None:
            try:
                evidence.emit(
                    "stopped",
                    reason=message,
                    sqlstate=code if isinstance(code, str) and re.fullmatch("[0-9A-Z]{5}", code) else None,
                )
            except OSError:
                pass  # Evidence failure is itself a stop, never a reason to continue.
        print(message)
        return 2
    finally:
        if evidence is not None:
            try:
                evidence.close()
            except OSError:
                pass
