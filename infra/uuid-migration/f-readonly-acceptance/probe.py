"""Exactly-one-connection F observation lifecycle, dependency injected/inert."""

from __future__ import annotations

import json
import os
import stat
import time
from datetime import UTC, datetime
from pathlib import Path

import catalog

from security import LIMITS, TARGET, require, safe_error, sha

OPTIONS = {
    **TARGET,
    "autocommit": True,
    "passfile": "/dev/null",
    "sslmode": "disable",
    "gssencmode": "disable",
    "connect_timeout": 5,
    "prepare_threshold": None,
    "application_name": "sbom_w24e_f_readonly",
    "options": "-c default_transaction_read_only=on -c statement_timeout=2000 -c lock_timeout=250 "
    "-c idle_in_transaction_session_timeout=5000 -c row_security=on -c search_path=pg_catalog "
    "-c check_function_bodies=on -c stats_fetch_consistency=none",
}


class Budget:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.started = clock()
        self.queries = self.controls = self.attempts = self.rows = 0

    def check(self):
        require(self.clock() - self.started < LIMITS["cooperative_seconds"], "Cooperative client window exhausted")

    def reserve(self, kind, *, cleanup=False):
        if not cleanup:
            self.check()
        limit = LIMITS[kind]
        value = getattr(self, kind)
        require(value < limit, "Budget exhausted: " + kind)
        setattr(self, kind, value + 1)


class Evidence:
    def __init__(self, path):
        p = Path(path)
        require(p.is_absolute() and ".." not in p.parts, "Absolute private evidence path")
        require(
            not any(q.is_symlink() for q in (p, *p.parents)) and not p.exists(), "Evidence claim already exists/symlink"
        )
        s = p.parent.stat()
        require(stat.S_IMODE(s.st_mode) == 0o700 and s.st_uid == os.getuid(), "Private evidence parent")
        self.fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self.previous = "0" * 64
        try:
            self.record("CLAIMED")
            fd = os.open(p.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except BaseException:
            self.close()
            raise

    def record(self, event, **fields):
        row = {"event": event, "utc": datetime.now(UTC).isoformat(), "previous_sha256": self.previous, **fields}
        raw = (json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
        require(len(raw) <= 524288, "Evidence row too large")
        require(os.write(self.fd, raw) == len(raw), "Short evidence write")
        os.fsync(self.fd)
        self.previous = sha(raw)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def status(connection):
    return connection.info.transaction_status.name


class Probe:
    def __init__(self, authority, budget, evidence, *, snapshot, verify_resources, correlate, connector, dependencies):
        self.authority, self.budget, self.evidence = authority, budget, evidence
        self.dependencies = dependencies
        self.snapshot, self.verify_resources, self.correlate, self.connector = (
            snapshot,
            verify_resources,
            correlate,
            connector,
        )
        self.constructor_attempts = 0
        self.connection = self.secret = None
        self.begun = False
        self.closed = False
        self.rollback_ack = False
        self.rollback_sent = False
        self.observed = {}
        self.baseline = None

    def query(self, key):
        require(key in catalog.QUERIES, "Unapproved SQL observation")
        self.authority.recheck()
        self.budget.reserve("queries")
        sql = catalog.QUERIES[key]
        require(sha(sql.encode()) == self.authority.plan["sql_sha256"][key], "SQL source changed")
        self.evidence.record("QUERY_REQUESTED", name=key, sql_sha256=sha(sql.encode()))
        require(status(self.connection) == "INTRANS", "Read-only transaction lost/aborted")
        with self.connection.cursor() as cur:
            cur.execute(sql)
            rows = cur.fetchmany(LIMITS["rows_per_query"] + 1)
            require(len(rows) <= LIMITS["rows_per_query"], "Catalog result row limit")
            columns = [d.name for d in cur.description]
            require(len(columns) == len(set(columns)), "Ambiguous catalog columns")
            result = [dict(zip(columns, row, strict=True)) for row in rows]
        self.budget.rows += len(result)
        require(self.budget.rows <= LIMITS["total_rows"], "Total catalog row limit")
        self.budget.check()
        self.evidence.record("CATALOG", name=key, rows=result)
        return result

    def control(self, sql, *, cleanup=False):
        require(sql in {"BEGIN READ ONLY", "ROLLBACK"}, "Mutation/COMMIT/control refused")
        if not cleanup:
            self.budget.check()
        try:
            self.evidence.record("CONTROL_REQUESTED", control=sql)
        except Exception:
            if not cleanup:
                raise
        self.budget.reserve("controls", cleanup=cleanup)
        if sql == "ROLLBACK":
            self.rollback_sent = True
        with self.connection.cursor() as cur:
            cur.execute(sql)
        require(
            status(self.connection) == ("INTRANS" if sql.startswith("BEGIN") else "IDLE"),
            "Transaction control not acknowledged",
        )
        if sql == "ROLLBACK":
            self.rollback_ack = True
        else:
            self.begun = True

    def run(self, baseline):
        failure = None
        assessment = None
        preserved = False
        success = False
        authentication_passed = False
        try:
            self.authority.recheck()
            self.baseline = baseline
            self.verify_resources(self.snapshot(), baseline)
            self.secret = self.correlate(self.authority.plan["credential_metadata"])
            self.authority.recheck()  # original raw bytes/source/expiry immediately before auth
            self.verify_resources(self.snapshot(), baseline)
            self.authority.recheck()
            self.dependencies()
            self.authority.recheck()
            self.budget.reserve("attempts")
            self.evidence.record("CONNECT_REQUESTED", manifest_sha256=self.authority.expected)
            self.constructor_attempts += 1
            self.connection = self.connector(**OPTIONS, password=self.secret.decode("ascii"))
            require(self.connection.autocommit is True and status(self.connection) == "IDLE", "Unexpected driver state")
            used = self.connection.pgconn.used_password
            self.evidence.record("CONNECTED", libpq_used_password=bool(used), credential_correlated=True)
            require(used is True, "UNKNOWN: libpq did not establish password-based authentication")
            authentication_passed = True
            self.control("BEGIN READ ONLY")
            ip = self.verify_resources(baseline, baseline)
            first = self.query("identity")
            catalog.identity(catalog.one(first, "identity"), ip)
            self.observed["identity"] = first
            for key in catalog.QUERIES:
                if key != "identity":
                    self.observed[key] = self.query(key)
            assessment = catalog.validate(self.observed, ip, used)
            # Stats consistency=none avoids a cached pg_stat_activity snapshot.
            require(self.query("identity") == first, "Database identity changed during session")
            require(self.query("clients") == [] and self.query("locks") == [], "Late competing client/lock")
            self.authority.recheck()
            self.budget.check()
            self.control("ROLLBACK")
            self.evidence.record("ROLLBACK_ACKNOWLEDGED")
            success = True
        except Exception as error:
            failure = safe_error(error, self.secret or b"")
            try:
                self.evidence.record("FAILURE", **failure)
            except Exception:
                pass  # cleanup must still run when evidence is unavailable
        finally:
            if self.connection is not None:
                try:
                    active = status(self.connection) in {"INTRANS", "INERROR"}
                    if not self.rollback_sent and active:
                        self.control("ROLLBACK", cleanup=True)
                except Exception as error:
                    success = False
                    failure = failure or safe_error(error, self.secret or b"")
                try:
                    self.connection.close()
                    self.closed = bool(self.connection.closed)
                except Exception as error:
                    failure = failure or safe_error(error, self.secret or b"")
                if not self.closed:
                    success = False
            if isinstance(self.secret, bytearray):
                self.secret[:] = b"\0" * len(self.secret)
            self.secret = None
        try:
            self.authority.recheck()
            self.verify_resources(self.snapshot(), baseline)
            preserved = True
            self.evidence.record("CLOSED", physical_closed=self.closed, rollback_ack=self.rollback_ack)
        except Exception as error:
            success = False
            failure = failure or safe_error(error)
        complete = bool(
            success
            and preserved
            and assessment is not None
            and authentication_passed
            and self.rollback_ack
            and self.closed
        )
        result = {
            "scope": "COMPLETE_READ_ONLY_PROBE",
            "status": "READ_ONLY_ACCEPTED" if complete else "BLOCKED_OR_INCOMPLETE",
            "accepted": complete,
            "checks": {
                "catalog_observations": "PASS" if assessment is not None else "FAIL_OR_INCOMPLETE",
                "authentication_evidence": "PASS" if authentication_passed else "FAIL_OR_INCOMPLETE",
                "transaction_rollback": "PASS" if self.rollback_ack else "NOT_ACKNOWLEDGED",
                "physical_closure": "PASS" if self.closed else "NOT_CONFIRMED",
                "infrastructure_preservation": "PASS" if preserved else "FAIL_OR_INCOMPLETE",
            },
            "assessment": assessment,
            "failure": failure,
            "attempts": self.constructor_attempts,
            "attempt_budget_reservations": self.budget.attempts,
            "queries": self.budget.queries,
            "controls": self.budget.controls,
            "closed": self.closed,
            "rollback_ack": self.rollback_ack,
            "resources_preserved": preserved,
            "connection_handle_returned": self.connection is not None,
            "migrations": 0,
            "live_integrity_cases": 0,
        }
        self.evidence.record("STOP", result=result)
        return result
