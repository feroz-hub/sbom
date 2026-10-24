"""Executable UUID integrity cases. Default/offline mode never connects.

Connected modes require a separately accepted, approved disposable E; D is forbidden.
Fixtures are committed synthetic rows retained on E, never deleted by this suite.
"""

from __future__ import annotations

import argparse
import json
import os
import threading
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import uuid_integrity_control as ctl
import uuid_integrity_fixtures as fx
from psycopg import sql

V4 = uuid.UUID("00000000-0000-4000-8000-000000000017")
OTHER = uuid.UUID("00000000-0000-4000-8000-000000000018")
INVALID = {
    "v1": "00000000-0000-1000-8000-000000000017",
    "v5": "00000000-0000-5000-8000-000000000017",
    "variant": "00000000-0000-4000-0000-000000000017",
    "nil": "00000000-0000-0000-0000-000000000000",
    "malformed": "synthetic-not-a-uuid",
    "integer_type": 17,
}
CASES = {
    "generation": ("omitted", "explicit_null", "supplied", "uppercase", "duplicates_permitted"),
    "validation": tuple(INVALID) + ("new_row_not_valid_enforcement",),
    "immutability": (
        "replace",
        "remove",
        "same",
        "unrelated",
        "default_reassign",
        "legacy_null_first",
        "legacy_null_same",
        "legacy_null_invalid",
    ),
    "concurrency": (
        "parallel_insert",
        "parallel_reassign",
        "parallel_null_first",
        "row_lock_timeout",
        "component_self_reference",
    ),
    "failure": ("check_savepoint", "trigger_savepoint", "partial_savepoint", "statement_timeout", "aborted_rollback"),
    "interference": ("before_update_early", "before_update_late", "before_update_restore_final"),
}


def cases(tables, categories):
    return [
        (t, category, name)
        for t in tables
        for category in categories
        for name in CASES[category]
        if name != "component_self_reference" or t == "sbom_component"
    ]


def check_uuid(row, expected=None):
    ctl.require(
        row is not None and type(row[0]) is int and isinstance(row[1], uuid.UUID) and row[2] == "uuid",
        "Expected native persisted UUID/integer identity",
    )
    ctl.require(row[1].version == 4 and row[1].variant == uuid.RFC_4122, "Expected UUIDv4 RFC variant")
    ctl.require(expected is None or row[1] == expected, "Persisted UUID changed")
    return row


def expect_error(conn, callback, state, table, trigger=False):
    """Nested psycopg transaction is a savepoint; assert rollback/SQLSTATE provenance."""
    try:
        with conn.transaction():
            callback()
    except Exception as error:
        ctl.require(getattr(error, "sqlstate", None) == state, "Unexpected SQLSTATE")
        constraint = getattr(getattr(error, "diag", None), "constraint_name", None)
        if state == "23514":
            ctl.require(
                constraint is None if trigger else constraint == f"ck_{table}_public_id_v4",
                "CHECK versus identity-trigger rejection mismatch",
            )
        return ctl.classify(error)
    raise ctl.Stop("Expected failure did not occur")


# E-only helper is created/dropped within owned transactions; never disables a guard.
# A late INSERT helper models pre-expand legacy NULL state after the normal allocator.
HELPER_SQL = """
CREATE FUNCTION public.w17_integrity_before_v1() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $w17$
BEGIN
 IF TG_TABLE_SCHEMA <> 'public' OR TG_NARGS <> 1 THEN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='Unsupported synthetic fixture';
 END IF;
 IF TG_OP='INSERT' THEN NEW.public_id := NULL;
 ELSIF TG_OP='UPDATE' THEN
  IF TG_ARGV[0]='restore' THEN NEW.public_id := OLD.public_id;
  ELSE NEW.public_id := TG_ARGV[0]::pg_catalog.uuid; END IF;
 ELSE RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='Unsupported synthetic operation';
 END IF;
 RETURN NEW;
END;
$w17$
"""


def helper(conn, table, row_id, operation, early=False, create_function=True, restore=False):
    ctl.require(table in fx.TABLES and operation in ("INSERT", "UPDATE"), "Unapproved helper target")
    name = "aa_w17_integrity_before" if early else "zz_w17_integrity_before"
    if create_function:
        conn.execute(HELPER_SQL)
    conn.execute(
        sql.SQL(
            "CREATE TRIGGER {} BEFORE {} ON public.{} FOR EACH ROW WHEN (NEW.id={}) "
            "EXECUTE FUNCTION public.w17_integrity_before_v1({})"
        ).format(
            sql.Identifier(name),
            sql.SQL(operation),
            sql.Identifier(table),
            sql.Literal(row_id),
            sql.Literal("restore" if restore else str(OTHER)),
        )
    )
    return name


def remove_helper(conn, table, name, drop_function=True):
    ctl.require(
        table in fx.TABLES and name in ("aa_w17_integrity_before", "zz_w17_integrity_before"),
        "Only this suite's exact helper may be removed",
    )
    conn.execute(sql.SQL("DROP TRIGGER {} ON public.{}").format(sql.Identifier(name), sql.Identifier(table)))
    if drop_function:
        conn.execute("DROP FUNCTION public.w17_integrity_before_v1()")


class Suite:
    def __init__(self, sessions):
        self.sessions = sessions
        self.slot = 0
        self.slot_lock = threading.Lock()

    def next_slot(self):
        with self.slot_lock:
            self.slot += 1
            ctl.require(self.slot <= fx.MAX_SLOT, "Fixture slot budget exhausted")
            return self.slot

    def fixture(self, table, mode="omitted", supplied=None, legacy=False):
        slot = self.next_slot()

        def build(conn):
            name = helper(conn, table, fx.identity(table, slot), "INSERT") if legacy else None
            row = fx.insert_chain(conn, table, slot, self.sessions.reserve_row, mode, supplied)
            if name:
                remove_helper(conn, table, name)
                ctl.require(row[1] is None, "Legacy NULL fixture was not constructed")
            else:
                check_uuid(row, uuid.UUID(str(supplied)) if mode == "supplied" else None)
            return row

        row = ctl.acknowledged_fixture(self.sessions, build)
        with self.sessions.open() as reader:
            persisted = fx.read_identity(reader, table, row[0])
            ctl.require(persisted == row, "Independent fixture committed read-back mismatch")
        return row

    def readback(self, table, row):
        with self.sessions.open() as conn:
            actual = fx.read_identity(conn, table, row[0])
            ctl.require(actual == row, "Independent identity preservation failed")

    def generation(self, table, name):
        if name == "duplicates_permitted":
            one = self.fixture(table, "supplied", V4)
            two = self.fixture(table, "supplied", V4)
            ctl.require(one[0] != two[0] and one[1] == two[1], "Transitional duplicate semantics changed")
            return {"observed": "duplicate explicit v4 allowed; no unique public_id index"}
        mode = {"omitted": "omitted", "explicit_null": "null", "supplied": "supplied", "uppercase": "supplied"}[name]
        value = "ABCDEFAB-CDEF-4ABC-8ABC-ABCDEFABCDEF" if name == "uppercase" else V4
        row = self.fixture(table, mode, value)
        check_uuid(row)
        return {"committed_readback": True, "native_uuid_v4_variant": True, "integer_FKs": True}

    def validation(self, table, name):
        kind = "v1" if name == "new_row_not_valid_enforcement" else name
        slot = self.next_slot()
        with self.sessions.open() as conn:
            with ctl.write_transaction(conn):
                observed = expect_error(
                    conn,
                    lambda: fx.insert_chain(conn, table, slot, self.sessions.reserve_row, "supplied", INVALID[kind]),
                    "22P02" if kind == "malformed" else "42804" if kind == "integer_type" else "23514",
                    table,
                )
                ctl.require(conn.execute("SELECT 1").fetchone() == (1,), "Savepoint did not recover transaction")
        with self.sessions.open() as reader:
            ctl.require(fx.read_identity(reader, table, fx.identity(table, slot)) is None, "Rejected insert persisted")
        return {
            **observed,
            "new_row_CHECK_enforced": kind not in ("malformed", "integer_type"),
            "savepoint_and_independent_absence": True,
        }

    def immutability(self, table, name):
        legacy = name.startswith("legacy_null")
        row = self.fixture(table, "supplied", V4, legacy=legacy)
        observed = {}
        with self.sessions.open() as conn:
            with ctl.write_transaction(conn):
                if name in ("replace", "remove"):
                    observed = expect_error(
                        conn,
                        lambda: fx.update(conn, table, row[0], "public_id", OTHER if name == "replace" else None),
                        "23514",
                        table,
                        trigger=True,
                    )
                elif name == "same":
                    ctl.require(
                        fx.update(conn, table, row[0], "public_id", row[1]).rowcount == 1, "Same UUID update failed"
                    )
                elif name == "default_reassign":
                    observed = expect_error(
                        conn,
                        lambda: conn.execute(
                            sql.SQL("UPDATE public.{} SET public_id=DEFAULT WHERE id=%s").format(sql.Identifier(table)),
                            (row[0],),
                        ),
                        "23514",
                        table,
                        trigger=True,
                    )
                elif name == "legacy_null_invalid":
                    observed = expect_error(
                        conn, lambda: fx.update(conn, table, row[0], "public_id", INVALID["v1"]), "23514", table
                    )
                elif name == "legacy_null_first":
                    ctl.require(
                        fx.update(conn, table, row[0], "public_id", V4).rowcount == 1, "First UUID assignment failed"
                    )
                    row = (row[0], V4, "uuid")
                elif name == "legacy_null_same":
                    ctl.require(
                        fx.update(conn, table, row[0], "public_id", None).rowcount == 1, "NULL-to-NULL update failed"
                    )
                    fx.update(conn, table, row[0], fx.NAME_COLUMN[table], "synthetic-w17-unrelated")
                else:
                    ctl.require(
                        fx.update(conn, table, row[0], fx.NAME_COLUMN[table], "synthetic-w17-unrelated").rowcount == 1,
                        "Unrelated update missing",
                    )
                ctl.require(fx.read_identity(conn, table, row[0]) == row, "Unexpected identity change")
        self.readback(table, row)
        return {**observed, "independent_preservation": True, "legacy_null_fixture": legacy}

    def parallel(self, workers):
        ctl.require(len(workers) == 2, "Exactly two parallel clients")
        barrier = threading.Barrier(2, timeout=5)

        def run(worker):
            try:
                barrier.wait()
                return worker()
            except BaseException:
                self.sessions.cancelled.set()
                raise

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(run, worker) for worker in workers]
            return [f.result(timeout=20) for f in futures]

    def concurrency(self, table, name):
        if name == "parallel_insert":

            def insert_sample():
                return [self.fixture(table)[1] for _ in range(4)]

            results = self.parallel([insert_sample, insert_sample])
            ctl.require(len(set(results[0] + results[1])) == 8, "Observed generated sample collision")
            return {"sample": 8, "observed_unique": True, "global_uniqueness_enforced": False}
        if name == "component_self_reference":
            row = self.fixture(table)
            with self.sessions.open() as conn:
                with ctl.write_transaction(conn):
                    ctl.require(
                        fx.update(conn, table, row[0], "duplicate_of_component_id", row[0]).rowcount == 1,
                        "Component self-reference update failed",
                    )
                    observed = expect_error(
                        conn,
                        lambda: fx.update(conn, table, row[0], "duplicate_of_component_id", 2147483646),
                        "23503",
                        table,
                    )
                    ctl.require(
                        conn.execute(
                            "SELECT duplicate_of_component_id FROM public.sbom_component WHERE id=%s", (row[0],)
                        ).fetchone()
                        == (row[0],),
                        "Self-reference rollback failed",
                    )
            self.readback(table, row)
            return {**observed, "integer_self_reference": True}
        row = self.fixture(
            table, "supplied", uuid.UUID("00000000-0000-4000-8000-000000000019"), legacy=name == "parallel_null_first"
        )
        if name == "row_lock_timeout":
            with self.sessions.open() as holder:
                with ctl.write_transaction(holder):
                    holder.execute(
                        sql.SQL("SELECT id FROM public.{} WHERE id=%s FOR UPDATE").format(sql.Identifier(table)),
                        (row[0],),
                    )
                    with self.sessions.open() as waiter:
                        with ctl.write_transaction(waiter):
                            result = expect_error(
                                waiter,
                                lambda: fx.update(waiter, table, row[0], fx.NAME_COLUMN[table], "synthetic-w17-locked"),
                                "55P03",
                                table,
                            )
            self.readback(table, row)
            return {**result, "post_rollback_readback": True}

        ready = threading.Barrier(2, timeout=5)

        def writer(value):
            with self.sessions.open() as conn:
                with ctl.write_transaction(conn):
                    ready.wait()  # both independent PostgreSQL transactions exist before either UPDATE
                    if name == "parallel_reassign":
                        return expect_error(
                            conn,
                            lambda: fx.update(conn, table, row[0], "public_id", value),
                            "23514",
                            table,
                            trigger=True,
                        )
                    return fx.update(conn, table, row[0], "public_id", value, null_only=True).rowcount

        result = self.parallel([lambda: writer(V4), lambda: writer(OTHER)])
        if name == "parallel_null_first":
            ctl.require(sorted(result) == [0, 1], "NULL-only concurrent assignment winner mismatch")
            with self.sessions.open() as reader:
                final = check_uuid(fx.read_identity(reader, table, row[0]))
                ctl.require(final[1] in (V4, OTHER), "Unexpected concurrent UUID winner")
        else:
            self.readback(table, row)
        return {"clients": 2, "conditional_assignment" if name == "parallel_null_first" else "rejections": True}

    def failure(self, table, name):
        if name == "aborted_rollback":
            slot = self.next_slot()
            with self.sessions.open() as conn:
                conn.execute("BEGIN READ WRITE")
                try:
                    try:
                        fx.insert_chain(conn, table, slot, self.sessions.reserve_row, "supplied", INVALID["v5"])
                    except Exception as error:
                        ctl.require(getattr(error, "sqlstate", None) == "23514", "Expected CHECK abort")
                    else:
                        raise ctl.Stop("Expected transaction failure absent")
                    try:
                        conn.execute("SELECT 1")
                    except Exception as error:
                        ctl.require(getattr(error, "sqlstate", None) == "25P02", "Expected aborted transaction state")
                    else:
                        raise ctl.Stop("Expected transaction abort state absent")
                finally:
                    conn.execute("ROLLBACK")
            with self.sessions.open() as reader:
                ctl.require(
                    fx.read_identity(reader, table, fx.identity(table, slot)) is None, "Rollback insert remained"
                )
            return {"sqlstate": "25P02", "check_sqlstate": "23514", "independent_rollback_absence": True}
        row = self.fixture(table, "supplied", V4)
        with self.sessions.open() as conn:
            with ctl.write_transaction(conn):
                if name == "statement_timeout":
                    conn.execute("SET LOCAL statement_timeout='50ms'")
                    result = expect_error(conn, lambda: conn.execute("SELECT pg_catalog.pg_sleep(0.2)"), "57014", table)
                    conn.execute("SET LOCAL statement_timeout='2s'")
                elif name == "trigger_savepoint":
                    result = expect_error(
                        conn, lambda: fx.update(conn, table, row[0], "public_id", OTHER), "23514", table, trigger=True
                    )
                else:
                    if name == "partial_savepoint":
                        fx.update(conn, table, row[0], fx.NAME_COLUMN[table], "synthetic-w17-before-savepoint")
                    result = expect_error(
                        conn, lambda: fx.update(conn, table, row[0], "public_id", INVALID["v1"]), "23514", table
                    )
                    if name == "partial_savepoint":
                        actual = conn.execute(
                            sql.SQL("SELECT {} FROM public.{} WHERE id=%s").format(
                                sql.Identifier(fx.NAME_COLUMN[table]), sql.Identifier(table)
                            ),
                            (row[0],),
                        ).fetchone()
                        ctl.require(
                            actual == ("synthetic-w17-before-savepoint",), "Outer write lost on savepoint failure"
                        )
                ctl.require(fx.read_identity(conn, table, row[0]) == row, "Failed statement changed identity")
        self.readback(table, row)
        return {**result, "independent_preservation": True}

    def interference(self, table, name):
        row = self.fixture(table, "supplied", V4)
        with self.sessions.open() as conn:
            with ctl.write_transaction(conn):
                if name == "before_update_restore_final":
                    early = helper(conn, table, row[0], "UPDATE", early=True)
                    late = helper(conn, table, row[0], "UPDATE", create_function=False, restore=True)
                    ctl.require(
                        fx.update(conn, table, row[0], fx.NAME_COLUMN[table], "synthetic-w17-restored").rowcount == 1,
                        "Final unchanged UUID was unexpectedly rejected",
                    )
                    ctl.require(
                        fx.read_identity(conn, table, row[0]) == row, "BEFORE ordering did not restore identity"
                    )
                    remove_helper(conn, table, early, drop_function=False)
                    remove_helper(conn, table, late)
                    result = {"final_identity_unchanged": True, "two_BEFORE_triggers_ordered": True}
                else:
                    result = self.rejected_interference(conn, table, row, name)
        self.readback(table, row)
        return result

    def rejected_interference(self, conn, table, row, name):
        trigger = helper(conn, table, row[0], "UPDATE", early=name == "before_update_early")
        result = expect_error(
            conn,
            lambda: fx.update(conn, table, row[0], fx.NAME_COLUMN[table], "synthetic-w17-before-interference"),
            "23514",
            table,
            trigger=True,
        )
        ctl.require(fx.read_identity(conn, table, row[0]) == row, "AFTER guard missed BEFORE interference")
        remove_helper(conn, table, trigger)
        return {**result, "BEFORE_interference_rejected": True}

    def run(self, selected):
        ctl.require(len(selected) <= self.sessions.plan["max_cases"], "Case budget exceeded")
        for i, (table, category, name) in enumerate(selected):
            self.sessions.budget()
            ctl.require(self.sessions.plan["source_sha256"] == ctl.source_hashes(), "Source drift during suite")
            ctl.verify_resources(self.sessions.plan)
            with self.sessions.open() as conn:
                self.sessions.baseline(conn)
                ctl.require(
                    conn.execute(
                        "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() "
                        "AND backend_type='client backend' AND pid<>pg_backend_pid() AND pid<>%s",
                        (self.sessions.keeper_pid,),
                    ).fetchone()
                    == (0,),
                    "Competing E client found",
                )
            self.sessions.evidence.emit("case_start", table=table, category=category, case=name)
            try:
                result = getattr(self, category)(table, name)
                with self.sessions.open() as conn:
                    self.sessions.baseline(conn)
                self.sessions.evidence.emit(
                    "case_result", table=table, category=category, case=name, status="PASS", **result
                )
            except BaseException as error:
                self.sessions.evidence.emit(
                    "case_result", table=table, category=category, case=name, status="FAIL", **ctl.classify(error)
                )
                for t, cat, n in selected[i + 1 :]:
                    self.sessions.evidence.emit(
                        "case_result", table=t, category=cat, case=n, status="SKIP", reason="stopped_after_failure"
                    )
                raise


def proposal():
    """Offline proposal, NOT an executable approval or a provisioner."""
    return {
        "task": "W1.7A",
        "target": "E",
        "accepted": False,
        "host": "127.0.0.1",
        "port": 56042,
        "database": "uuid_w17_e_integrity",
        "user": "uuid_w1_d_bootstrap",
        "password_file": str(ctl.PASSWORD),
        "source_D085": {"runner13": ctl.D13, "independent31": ctl.D31},
        "source_sha256": ctl.source_hashes(),
        "expires_utc": (datetime.now(UTC) + timedelta(hours=24)).isoformat(),
        "container_id": None,
        "network_id": None,
        "volume_sha256": None,
        "system_identifier": None,
        "database_oid": None,
        "server_address": None,
        "postmaster_started_at": None,
        "e_schema_sha256": None,
        "preservation_sha256": None,
        "credential_metadata": None,
        "synthetic_only_reviewed": False,
        "schema_parity_reviewed": False,
        "privileges_and_writers_reviewed": False,
        "credential_provenance_reviewed": False,
        "exclusive_test_window_reviewed": False,
        "fixture_ddl_reviewed": False,
        "outbound_risk_reviewed": False,
        "approvals": {},
        "tables": list(fx.TABLES),
        "categories": list(CASES),
        "max_connections": 2048,
        "max_rows": 5000,
        "max_cases": 256,
        "max_seconds": 900,
        "resources": {
            "project": "sbom-uuid-w17-e",
            "service": "postgres_e",
            "image_id": ctl.IMAGE,
            "volume": "sbom-uuid-w17-e_e_pgdata",
            "network": "sbom-uuid-w17-e_e_access",
            "socket": ctl.SOCKET,
            "daemon": ctl.DAEMON,
            "cpus": 1,
            "memory_mb": 512,
            "shm_mb": 64,
            "pids_limit": 128,
            "network_driver": "bridge",
            "internal": False,
            "gateway_mode_ipv4": "nat",
            "enable_icc": False,
            "enable_ip_masquerade": True,
            "publication": "127.0.0.1:56042:5432",
            "restart": "no",
            "pull": "never",
            "build": False,
            "password_mount": "/run/secrets/e_password:ro",
            "pgdata": "/var/lib/postgresql/data/pgdata",
            "environment": {
                "POSTGRES_USER": "uuid_w1_d_bootstrap",
                "POSTGRES_DB": "uuid_w17_e_integrity",
                "POSTGRES_PASSWORD_FILE": "/run/secrets/e_password",
                "PGDATA": "/var/lib/postgresql/data/pgdata",
            },
            "postgres_settings": {
                "max_connections": 12,
                "shared_buffers": "64MB",
                "work_mem": "4MB",
                "statement_timeout": "2s",
                "lock_timeout": "250ms",
                "idle_in_transaction_session_timeout": "5s",
            },
            "healthcheck": {
                "test": ["CMD", "pg_isready", "-U", "uuid_w1_d_bootstrap", "-d", "uuid_w17_e_integrity"],
                "interval": "5s",
                "timeout": "3s",
                "retries": 12,
            },
        },
        "baseline_procedure": [
            "New E-only OS-random secret, private0700/0600, no reuse",
            "Fresh collision/capacity/image/port/source-D identity approval before provisioning",
            "Separate reviewed D-only schema export authorization; no data/sequence positions",
            "Review full schema archive SQL/TOC; reproduce exact owners/ACLs/restricted roles",
            "One E schema-only single-transaction restore; no clean/no-owner/no-acl",
            "Independent structural/security parity; no inherited blanket ownership exception",
            "Separate explicit E-only insert of sole085 marker, no migration replay",
            "Accept E identity/catalog/parity, then independent target-specific test manifest review",
        ],
        "fixture_scope": "Committed synthetic negative integer PK hierarchies only; no auto DELETE/TRUNCATE/sequence reset",
        "fixture_DDL": "E-only w17_integrity_before_v1 helper plus aa/zz row-filtered INSERT/UPDATE trigger; exact DROP before commit; never disables/replaces existing guards",
        "teardown": "Not automated; separate approval pins exact E container/network/volume/cluster; retain on failure, no wildcard/down/prune",
        "network_risk": "Ordinary bridge permits outbound access including host-published services; ICC=false is not an egress firewall",
        "space_gate": "Before provisioning/export: independently observe >=2GiB available host/Docker storage and >=1GiB memory headroom; stop if budget unavailable; no claim of current capacity",
        "approval_stages": [
            "independent review of this exact offline resource/schema-copy/role/credential/egress/fixture-DDL proposal",
            "separate E-only provisioning and D-schema export/E restore/marker authorization",
            "accept actual E structural/security parity and new identity; create fresh execution candidate",
            "operator approval of actual E pins/expiry/source hashes/categories/budgets and distinct integrity_validate/integrity_execute references",
        ],
        "fault_injection": "Termination/network/PG restart/storage failures NOT IMPLEMENTED for automatic execution; separate destructive authority",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("offline", "list", "proposal", "validate", "execute"), default="offline")
    parser.add_argument("--target", choices=("E",))
    parser.add_argument("--plan")
    parser.add_argument("--approval-id")
    parser.add_argument("--evidence")
    parser.add_argument("--output")
    parser.add_argument("--table", choices=fx.TABLES, action="append")
    parser.add_argument("--category", choices=ctl.CATEGORIES, action="append")
    args = parser.parse_args(argv)
    evidence = None
    try:
        fx.verify_contract()
        tables = args.table or list(fx.TABLES)
        categories = args.category or list(ctl.CATEGORIES)
        if args.mode in ("offline", "list", "proposal"):
            ctl.require(
                not any((args.target, args.plan, args.approval_id, args.evidence)),
                "Offline modes reject runtime inputs",
            )
            if args.mode == "offline":
                suite = unittest.defaultTestLoader.discover(str(ctl.HERE), pattern="test_uuid_integrity_offline.py")
                return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
            if args.mode == "list":
                print(json.dumps(cases(tables, categories)))
            else:
                ctl.require(bool(args.output), "New private proposal output required")
                value = proposal()
                # Reuse private-output controls; no credentials or DB connection.
                p = Path(args.output)
                ctl.require(
                    p.is_absolute() and not p.resolve().is_relative_to(ctl.ROOT), "Outside-checkout proposal required"
                )
                import stat

                s = p.parent.lstat()
                ctl.require(
                    not p.parent.is_symlink() and s.st_uid == os.getuid() and stat.S_IMODE(s.st_mode) == 0o700,
                    "Private0700 proposal parent required",
                )
                with os.fdopen(os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "w") as f:
                    json.dump(value, f, sort_keys=True, indent=2)
                    f.write("\n")
                    f.flush()
                    os.fsync(f.fileno())
                print(
                    json.dumps(
                        {
                            "status": "PENDING_OPERATOR_REVIEW",
                            "path": str(p),
                            "sha256": ctl.digest(value),
                            "byte_sha256": __import__("hashlib").sha256(p.read_bytes()).hexdigest(),
                        }
                    )
                )
            return 0
        ctl.require(
            args.target == "E" and all((args.plan, args.approval_id, args.evidence)) and not args.output,
            "Explicit E target/plan/action/evidence required",
        )
        plan = json.loads(ctl.common.private_file(args.plan))
        ctl.validate_plan(plan, "integrity_" + args.mode, args.approval_id, tables, categories)
        evidence = ctl.Evidence(args.evidence, plan)
        ctl.verify_resources(plan)
        sessions = ctl.Sessions(plan, evidence)
        with sessions.open() as keeper:
            sessions.baseline(keeper, empty=True)
            ctl.require(
                keeper.execute(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() "
                    "AND backend_type='client backend' AND pid<>pg_backend_pid()"
                ).fetchone()
                == (0,),
                "Competing E session before test window",
            )
            ctl.require(
                keeper.execute("SELECT pg_try_advisory_lock(%s)", (7160085085,)).fetchone() == (True,),
                "Another cooperating E operator holds lock",
            )
            sessions.keeper_pid = keeper.execute("SELECT pg_backend_pid()").fetchone()[0]
            if args.mode == "execute":
                Suite(sessions).run(cases(tables, categories))
            sessions.baseline(keeper)
            counts = sessions.final_data_scope(keeper)
            evidence.emit("synthetic_scope_verified", row_counts=counts)
        ctl.verify_resources(plan)
        evidence.emit(
            "completed_closed", mode=args.mode, connections=sessions.used, synthetic_row_attempts=sessions.rows
        )
        return 0
    except Exception as error:
        if evidence is not None:
            evidence.emit("STOP_NO_RETRY", **ctl.classify(error))
        print(json.dumps({"status": "STOP", **ctl.classify(error)}))
        return 2
    finally:
        if evidence is not None:
            evidence.close()


if __name__ == "__main__":
    raise SystemExit(main())
