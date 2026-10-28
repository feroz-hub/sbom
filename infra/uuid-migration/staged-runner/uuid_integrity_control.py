"""Fail-closed E-only authority, local resource, connection and evidence controls.

No I/O at import. Offline paths never invoke Docker, libpq or secret reading.
No provisioner, schema restorer, cleanup, retry or application initialization.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import expand_one_step as expand
import psycopg
import uuid_w1_common as common

ROOT = common.ROOT
HERE = Path(__file__).parent
REVISION = "085_uuid_sbom_component_expand"
D_CLUSTER = "7697252084555804711"
D_CONTAINER = "fb805a9c32dba2e30e01da6a70a26957fcf78caaa4f7bce73418a55a05b3696e"
D13 = "85507e89a3946cda7611e5498e816fcf5708af18a6549b08a4fbfe3ae1f0d80a"
D31 = "760c7e7b0b50688fd4f7c3471219a35fa3b025f67bf3303cc15a50f44800fd30"
IMAGE = "sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54"
DAEMON = "1f8c7fe5-5972-4adc-8d6e-363a38572be1"
DOCKER = "/Applications/Docker.app/Contents/Resources/bin/docker"
SOCKET = "/Users/ferozebasha/.docker/run/docker.sock"
DOCKER_SHA = "31ae2d64e51d9dfc728a2934941615cdd92f31279ed6d5c1fb2bfc0a44637a8f"
PASSWORD = Path.home() / ".sbom-uuid-w17-e/postgres-password"
CATEGORIES = ("generation", "validation", "immutability", "concurrency", "failure", "interference")
require = common.require
Stop = common.SafetyStop
digest = common.digest


def source_hashes():
    paths = [
        HERE / n
        for n in (
            "uuid_integrity_control.py",
            "uuid_integrity_fixtures.py",
            "uuid_integrity_suite.py",
            "uuid_integrity_fixture_catalog.json",
            "expand_one_step.py",
            "uuid_w1_common.py",
        )
    ]
    paths += sorted((HERE.parent / "staged-alembic").glob("*.py"))
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def validate_plan(plan, action, approval, tables, categories, now=None):
    """Pure validation before any Docker, file-secret or database access."""
    now = now or datetime.now(UTC)
    require(plan.get("target") == "E" and plan.get("accepted") is True, "Accepted E approval required")
    require(
        plan.get("host") == "127.0.0.1" and type(plan.get("port")) is int and plan["port"] == 56042,
        "Only E loopback56042 permitted; no A/B/D fallback",
    )
    require(
        plan.get("database") == "uuid_w17_e_integrity" and plan.get("user") == "uuid_w1_d_bootstrap",
        "Exact E identity required",
    )
    require(plan.get("password_file") == str(PASSWORD), "Dedicated new E credential only")
    for key in (
        "synthetic_only_reviewed",
        "schema_parity_reviewed",
        "privileges_and_writers_reviewed",
        "credential_provenance_reviewed",
        "exclusive_test_window_reviewed",
        "outbound_risk_reviewed",
    ):
        require(plan.get(key) is True, "Operator E attestations pending")
    require(action in ("integrity_validate", "integrity_execute"), "Unknown action")
    refs = plan.get("approvals", {})
    require(isinstance(approval, str) and bool(approval) and refs.get(action) == approval, "Action approval missing")
    require(
        all(isinstance(x, str) and x for x in refs.values()) and len(set(refs.values())) == len(refs),
        "Distinct explicit action approvals required",
    )
    expiry = datetime.fromisoformat(plan["expires_utc"])
    require(expiry.tzinfo is not None and expiry > now, "Approval expired or timezone absent")
    require(plan.get("source_D085") == {"runner13": D13, "independent31": D31}, "Source085 review mismatch")
    for key in ("container_id", "network_id", "e_schema_sha256", "volume_sha256", "preservation_sha256"):
        require(isinstance(plan.get(key), str) and re.fullmatch(r"[0-9a-f]{64}", plan[key]), "E identity pin missing")
    require(
        plan["container_id"] != D_CONTAINER
        and plan["network_id"] != "6a4a35eef52453d29e621d6ae192fe85b7c46768d8b16915a8a36713932d6e65",
        "D resource prohibited",
    )
    require(
        isinstance(plan.get("system_identifier"), str)
        and plan["system_identifier"].isdigit()
        and plan["system_identifier"] != D_CLUSTER,
        "New verified E cluster required",
    )
    require(type(plan.get("database_oid")) is int and plan["database_oid"] > 0, "E database OID missing")
    require(isinstance(plan.get("server_address"), str) and bool(plan["server_address"]), "E server interface missing")
    require(
        isinstance(plan.get("postmaster_started_at"), str) and bool(plan["postmaster_started_at"]),
        "E start pin missing",
    )
    require(plan.get("source_sha256") == source_hashes(), "Source changed since review")
    expand.discover()
    require(len(tables) == len(set(tables)) and len(categories) == len(set(categories)), "Duplicate test selections")
    require(
        set(tables) <= set(common.TABLES) and set(tables) <= set(plan.get("tables", [])) and bool(tables),
        "Unapproved tables",
    )
    require(
        set(categories) <= set(CATEGORIES) and set(categories) <= set(plan.get("categories", [])) and bool(categories),
        "Unapproved categories",
    )
    require(plan.get("fixture_ddl_reviewed") is True, "Legacy-NULL/BEFORE-trigger fixture DDL needs explicit approval")
    for key, limit in (("max_connections", 2048), ("max_rows", 5000), ("max_cases", 256), ("max_seconds", 900)):
        require(type(plan.get(key)) is int and 1 <= plan[key] <= limit, "Invalid execution budget")
    require(not any(k.startswith("PG") for k in os.environ), "Remove ambient libpq overrides")


def docker(*args):
    require(hashlib.sha256(Path(DOCKER).read_bytes()).hexdigest() == DOCKER_SHA, "Local Docker CLI changed")
    sock = Path(SOCKET).stat()
    require(stat.S_ISSOCK(sock.st_mode) and sock.st_uid == os.getuid(), "Local socket identity mismatch")
    result = subprocess.run(
        [DOCKER, "--host", "unix://" + SOCKET, *args],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={"HOME": str(Path.home()), "PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    require(result.returncode == 0, "Local metadata command failed")
    return json.loads(result.stdout)


def secret_mount(mounts, desktop):
    """Exact E path only; Desktop translation requires verified local context.

    Pure selector: it does not establish byte equivalence or read credentials.
    Both representations still require correlate_secret after all resource gates.
    """
    expected = "/Users/ferozebasha/.sbom-uuid-w17-e/postgres-password"
    require(str(PASSWORD) == expected, "Configured E secret path changed")
    selected = [m for m in mounts if m.get("Destination") == "/run/secrets/e_password"]
    require(len(selected) == 1, "Exactly one E secret mount required")
    mount = selected[0]
    allowed = {expected}
    if desktop is True:
        allowed.add("/host_mnt" + expected)
    require(
        mount.get("Type") == "bind" and mount.get("RW") is False and mount.get("Source") in allowed,
        "E secret mount mismatch",
    )
    return mount


def credential_metadata(info):
    return {
        "inode": info.st_ino,
        "uid": info.st_uid,
        "size": info.st_size,
        "mtime_ns": str(info.st_mtime_ns),
        "ctime_ns": str(info.st_ctime_ns),
    }


def correlate_secret(plan):
    """Bounded root initialization-context read; secret bytes never leave memory.

    Caller must first verify daemon, container, mount, exclusive storage/network
    and preservation. No SQL, credential fallback, logging, file copy or retry.
    Host inode is checked only against macOS provenance, never against VM inode.
    """
    require(plan.get("password_file") == str(PASSWORD), "Dedicated E credential required")
    require(
        not any(p.is_symlink() for p in (PASSWORD, *PASSWORD.parents))
        and str(PASSWORD.resolve(strict=True)) == str(PASSWORD),
        "E secret path must be canonical and symlink-free",
    )
    parent = PASSWORD.parent.lstat()
    require(
        parent.st_uid == os.getuid() and stat.S_IMODE(parent.st_mode) == 0o700,
        "E secret parent must be private",
    )
    fd = os.open(PASSWORD, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and before.st_uid == os.getuid()
            and stat.S_IMODE(before.st_mode) == 0o600
            and 0 < before.st_size <= 1048576,
            "E secret file privacy mismatch",
        )
        require(credential_metadata(before) == plan.get("credential_metadata"), "E secret provenance changed")
        raw = stream.read(1048577)
        require(len(raw) == before.st_size, "E secret read length changed")
        # CLI/socket were pinned by the preceding resource checks. Explicit endpoint,
        # root UID and fixed read-only script; no secret in argv, environment or logs.
        result = subprocess.run(
            [
                DOCKER,
                "--host",
                "unix://" + SOCKET,
                "exec",
                "--user",
                "0:0",
                plan["container_id"],
                "/bin/sh",
                "-c",
                'test "$(id -u)" = 0 && test -f /run/secrets/e_password '
                "&& test ! -L /run/secrets/e_password && test -r /run/secrets/e_password "
                "&& exec head -c 1048577 /run/secrets/e_password",
            ],
            capture_output=True,
            check=False,
            timeout=5,
            env={"HOME": str(Path.home()), "PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        require(result.returncode == 0, "E initialization-context secret read failed")
        equal = hmac.compare_digest(raw, result.stdout)
        del raw, result
        require(
            credential_metadata(os.fstat(stream.fileno())) == plan["credential_metadata"]
            and credential_metadata(PASSWORD.lstat()) == plan["credential_metadata"],
            "E secret changed during correlation",
        )
        require(equal, "E secret content correlation failed")
    return {"content_equal": True, "initialization_root_readable": True}


def verify_resources(plan):
    daemon = docker(
        "info",
        "--format",
        '{"id":{{json .ID}},"os":{{json .OperatingSystem}},"name":{{json .Name}},"type":{{json .OSType}}}',
    )
    require(isinstance(daemon, dict) and daemon.get("id") == DAEMON, "Local daemon changed")
    desktop = (
        sys.platform == "darwin"
        and daemon.get("os") == "Docker Desktop"
        and daemon.get("name") == "docker-desktop"
        and daemon.get("type") == "linux"
    )
    fmt = (
        '{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},'
        '"ports":{{json .NetworkSettings.Ports}},"mounts":{{json .Mounts}},'
        '"networks":{{json .NetworkSettings.Networks}},'
        '"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
        '"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
        '"limits":{"cpu":{{json .HostConfig.NanoCpus}},"memory":{{json .HostConfig.Memory}},'
        '"pids":{{json .HostConfig.PidsLimit}},"shm":{{json .HostConfig.ShmSize}}}}'
    )
    state = docker("container", "inspect", "--format", fmt, plan["container_id"])
    require(state["id"] == plan["container_id"] and state["running"] and state["image"] == IMAGE, "E container changed")
    require(state["project"] == "sbom-uuid-w17-e" and state["service"] == "postgres_e", "E project/service mismatch")
    require(
        state["limits"] == {"cpu": 1000000000, "memory": 512 * 1024**2, "pids": 128, "shm": 64 * 1024**2},
        "E resource limits changed",
    )
    require(state["ports"] == {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "56042"}]}, "E publication mismatch")
    require(set(state["networks"]) == {"sbom-uuid-w17-e_e_access"}, "E attached to unapproved network")
    require(state["networks"]["sbom-uuid-w17-e_e_access"]["NetworkID"] == plan["network_id"], "E network changed")
    data = [x for x in state["mounts"] if x["Destination"] == "/var/lib/postgresql/data"]
    require(
        len(data) == 1 and data[0]["Type"] == "volume" and data[0]["Name"] == "sbom-uuid-w17-e_e_pgdata",
        "E storage mismatch",
    )
    require(
        all(x["Destination"] in ("/var/lib/postgresql/data", "/run/secrets/e_password") for x in state["mounts"]),
        "Unexpected E mount",
    )
    secret_mount(state["mounts"], desktop)
    attached = docker(
        "ps", "-a", "--no-trunc", "--filter", "volume=sbom-uuid-w17-e_e_pgdata", "--format", "{{json .ID}}"
    )
    require(attached == plan["container_id"], "E volume not exclusive")
    volume = docker(
        "volume",
        "inspect",
        "--format",
        '{"name":{{json .Name}},"created":{{json .CreatedAt}},"driver":{{json .Driver}},"mountpoint":{{json .Mountpoint}}}',
        "sbom-uuid-w17-e_e_pgdata",
    )
    require(digest(volume) == plan["volume_sha256"], "E volume identity changed")
    network = docker("network", "inspect", "--format", "{{json .Containers}}", plan["network_id"])
    require(set(network) == {plan["container_id"]}, "Unexpected E network attachment")
    config = docker(
        "network",
        "inspect",
        "--format",
        '{"driver":{{json .Driver}},"internal":{{json .Internal}},"ipv6":{{json .EnableIPv6}},"options":{{json .Options}}}',
        plan["network_id"],
    )
    require(
        config["driver"] == "bridge" and config["internal"] is False and config["ipv6"] is False,
        "E bridge configuration mismatch",
    )
    for k, v in {
        "com.docker.network.bridge.enable_icc": "false",
        "com.docker.network.bridge.enable_ip_masquerade": "true",
        "com.docker.network.bridge.gateway_mode_ipv4": "nat",
    }.items():
        require(config["options"].get(k) == v, "Reviewed E bridge controls absent")
    require(digest(preservation()) == plan["preservation_sha256"], "Existing SBOM/D resources changed")
    correlate_secret(plan)


def preservation():
    """Filtered local metadata only; never contacts any PostgreSQL service."""
    observed = {}
    for name in (D_CONTAINER, "sbom-postgres-1", "sbom-redis-1", "sbom-mailpit-1"):
        observed[name] = docker(
            "container",
            "inspect",
            "--format",
            '{"id":{{json .Id}},"image":{{json .Image}},"started":{{json .State.StartedAt}},'
            '"state":{{json .State.Status}},"restarts":{{json .RestartCount}},'
            '"mounts":{{json .Mounts}},"ports":{{json .NetworkSettings.Ports}},'
            '"networks":{{json .NetworkSettings.Networks}}}',
            name,
        )
    for name in ("sbom-uuid-w1_d_pgdata", "sbom_postgres_data", "sbom_redis_data"):
        observed[name] = docker(
            "volume",
            "inspect",
            "--format",
            '{"name":{{json .Name}},"created":{{json .CreatedAt}},"mountpoint":{{json .Mountpoint}}}',
            name,
        )
    for name in ("sbom_default", "sbom-uuid-w1_d_access", "sbom-uuid-w1_d_private"):
        observed[name] = docker(
            "network",
            "inspect",
            "--format",
            '{"id":{{json .Id}},"containers":{{json .Containers}},"options":{{json .Options}}}',
            name,
        )
    return observed


def classify(error):
    code = getattr(error, "sqlstate", None)
    if code is not None and not re.fullmatch(r"[0-9A-Z]{5}", code):
        code = None
    kind = {
        "22P02": "uuid_type_conversion",
        "42804": "datatype_mismatch",
        "23514": "check_or_identity_trigger",
        "23503": "foreign_key",
        "23505": "unique_constraint",
        "55P03": "lock_timeout",
        "57014": "statement_timeout",
        "25P02": "transaction_aborted",
        "08006": "connection_lost",
    }.get(code, "exception")
    return {
        "sqlstate": code,
        "classification": "UNKNOWN_COMMIT_STOP" if isinstance(error, UnknownCommit) else kind,
        "exception_class": type(error).__name__,
    }


class Evidence:
    def __init__(self, path, plan):
        p = Path(path)
        require(p.is_absolute() and not p.resolve().is_relative_to(ROOT), "Private evidence path required")
        s = p.parent.lstat()
        require(
            not p.parent.is_symlink() and stat.S_IMODE(s.st_mode) == 0o700 and s.st_uid == os.getuid(),
            "Evidence parent must be owned0700",
        )
        self.stream = os.fdopen(os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "w")
        self.mutex = threading.Lock()
        try:
            self.emit("start", plan_sha256=digest(plan), target="E", cluster=plan["system_identifier"])
        except BaseException:
            self.stream.close()
            raise

    def emit(self, event, **fields):
        with self.mutex:
            self.stream.write(
                json.dumps({"utc": datetime.now(UTC).isoformat(), "event": event, **fields}, sort_keys=True) + "\n"
            )
            self.stream.flush()
            os.fsync(self.stream.fileno())

    def close(self):
        self.stream.close()


class Sessions:
    def __init__(self, plan, evidence):
        self.plan, self.evidence = plan, evidence
        self.used = self.rows = 0
        self.started = time.monotonic()
        self.mutex = threading.Lock()
        self.slots = threading.BoundedSemaphore(3)
        self.keeper_pid = None
        self.cancelled = threading.Event()
        self.fixture_ids = {table: set() for table in common.TABLES}

    def budget(self):
        require(not self.cancelled.is_set(), "Concurrent test failed; stop further work")
        require(time.monotonic() - self.started < self.plan["max_seconds"], "Client run budget exhausted")
        require(datetime.fromisoformat(self.plan["expires_utc"]) > datetime.now(UTC), "Approval expired")

    def reserve_row(self, table=None, row_id=None):
        with self.mutex:
            self.budget()
            require(self.rows < self.plan["max_rows"], "Synthetic row budget exhausted")
            self.rows += 1
            if table is not None:
                require(
                    table in common.TABLES and type(row_id) is int and -1700000000 < row_id < 0,
                    "Invalid synthetic fixture PK reservation",
                )
                self.fixture_ids[table].add(row_id)

    def final_data_scope(self, conn):
        """No business payload export: bounded negative PKs checked in memory only."""
        from psycopg import sql

        relations = conn.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename"
        ).fetchall()
        require(len(relations) == 72, "Unexpected E table inventory")
        counts = {}
        for (table,) in relations:
            if table == "alembic_version":
                continue
            if table in self.fixture_ids:
                rows = conn.execute(
                    sql.SQL("SELECT id FROM public.{} LIMIT 5001").format(sql.Identifier(table))
                ).fetchall()
                require(
                    len(rows) <= 5000 and {row[0] for row in rows} <= self.fixture_ids[table],
                    "Unexpected non-fixture E rows",
                )
                counts[table] = len(rows)
            else:
                require(
                    conn.execute(
                        sql.SQL("SELECT EXISTS(SELECT 1 FROM public.{})").format(sql.Identifier(table))
                    ).fetchone()
                    == (False,),
                    "Unexpected rows outside six-table synthetic scope",
                )
        return counts

    @contextmanager
    def open(self):
        self.budget()
        require(self.slots.acquire(timeout=5), "Connection concurrency cap reached")
        conn = None
        try:
            with self.mutex:
                require(self.used < self.plan["max_connections"], "Connection budget exhausted")
                self.used += 1
            # Never use common.connect: that function is specifically D-only.
            raw = common.private_file(self.plan["password_file"])
            s = Path(self.plan["password_file"]).stat()
            require(
                {
                    "inode": s.st_ino,
                    "uid": s.st_uid,
                    "size": s.st_size,
                    "mtime_ns": str(s.st_mtime_ns),
                    "ctime_ns": str(s.st_ctime_ns),
                }
                == self.plan["credential_metadata"],
                "E credential provenance changed",
            )
            conn = psycopg.connect(
                host="127.0.0.1",
                port=56042,
                dbname="uuid_w17_e_integrity",
                user="uuid_w1_d_bootstrap",
                password=raw.decode().strip(),
                passfile="/dev/null",
                sslmode="disable",
                connect_timeout=5,
                autocommit=True,
                application_name="uuid_w17_e_integrity",
                options="-c search_path=pg_catalog -c default_transaction_read_only=on "
                "-c statement_timeout=2000 -c lock_timeout=250 -c idle_in_transaction_session_timeout=5000",
            )
            del raw
            self.identity(conn)
            yield conn
        finally:
            if conn is not None:
                conn.close()
            self.slots.release()

    def identity(self, conn):
        row = conn.execute(common.IDENTITY_SQL).fetchone()
        require(
            row
            == (
                self.plan["database"],
                self.plan["user"],
                self.plan["user"],
                self.plan["database_oid"],
                self.plan["system_identifier"],
                16,
                self.plan["server_address"],
                5432,
                self.plan["postmaster_started_at"],
                False,
                "origin",
            ),
            "E PostgreSQL identity mismatch",
        )
        require(
            conn.execute(
                "SELECT current_setting('server_version_num')::int,current_setting('data_directory')"
            ).fetchone()
            == (160015, "/var/lib/postgresql/data/pgdata"),
            "PG16.15/E data directory required",
        )
        require(
            conn.execute(
                "SELECT pg_get_userbyid(datdba),datallowconn,datistemplate,datacl::text FROM pg_database "
                "WHERE datname=current_database()"
            ).fetchone()
            == ("uuid_w1_d_bootstrap", True, False, None),
            "E database ownership/security changed",
        )

    def baseline(self, conn, empty=False):
        self.budget()
        self.identity(conn)
        require(expand.marker(conn) == REVISION, "E revision mismatch")
        expand.prefix(conn, REVISION)
        for table in common.TABLES:
            rights = conn.execute(
                "SELECT has_table_privilege(%s,'INSERT'),has_table_privilege(%s,'UPDATE'),"
                "has_table_privilege(%s,'SELECT'),has_table_privilege(%s,'TRIGGER')",
                ("public." + table,) * 4,
            ).fetchone()
            require(rights == (True,) * 4, "Required synthetic test privileges missing")
        require(
            conn.execute(
                "SELECT EXISTS(SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid "
                "JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid "
                "AND a.attname='public_id' WHERE n.nspname='public' AND c.relname=ANY(%s) "
                "AND a.attnum=ANY(i.indkey))",
                (list(common.TABLES),),
            ).fetchone()
            == (False,),
            "Transitional tests forbid public UUID indexes",
        )
        state = expand.snapshot(conn)
        require(digest(state) == self.plan["e_schema_sha256"], "Approved E schema/security baseline changed")
        if empty:
            from psycopg import sql

            relations = conn.execute(
                "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename"
            ).fetchall()
            require(len(relations) == 72, "E schema incomplete")
            for (table,) in relations:
                if table != "alembic_version":
                    require(
                        conn.execute(
                            sql.SQL("SELECT EXISTS(SELECT 1 FROM public.{})").format(sql.Identifier(table))
                        ).fetchone()
                        == (False,),
                        "E must initially contain no business rows",
                    )
        return state


@contextmanager
def write_transaction(conn):
    """Known errors roll back; commit exceptions propagate without retry."""
    phase = "transaction"
    try:
        with conn.transaction():
            conn.execute("SET TRANSACTION READ WRITE")
            yield conn
            phase = "commit_pending"
    except BaseException as error:
        if phase == "commit_pending":
            raise UnknownCommit("Commit acknowledgement failed; no retry") from error
        raise


class UnknownCommit(Exception):
    """Never infer rollback or reconnect automatically after this outcome."""


def acknowledged_fixture(sessions, callback):
    with sessions.open() as conn:
        sessions.baseline(conn)
        phase = "transaction"
        try:
            with write_transaction(conn):
                result = callback(conn)
                sessions.budget()
                sessions.evidence.emit("fixture_precommit")
                phase = "commit_pending"
            phase = "committed"
            sessions.evidence.emit("fixture_commit_acknowledged")
        except BaseException:
            sessions.evidence.emit(
                "fixture_stopped",
                outcome="UNKNOWN_COMMIT_STOP"
                if phase == "commit_pending"
                else "COMMITTED_STOP"
                if phase == "committed"
                else "ROLLBACK_REQUIRES_READBACK",
            )
            raise
    return result  # physical close occurs before caller's independent read-back
