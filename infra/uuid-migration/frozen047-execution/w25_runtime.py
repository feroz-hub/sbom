"""Reviewed adapters, not a connected operation. Import performs no IO."""

from __future__ import annotations

from w25_inputs import require


def connection_options(action):
    require(action in {"unit_execute", "unit_readback"}, "Unsupported unit action")
    return {
        "host": "127.0.0.1",
        "hostaddr": "127.0.0.1",
        "port": 56043,
        "dbname": "uuid_w2_f_fresh",
        "user": "uuid_w2_f_bootstrap",
        "autocommit": False,
        "passfile": "/dev/null",
        "sslmode": "disable",
        "gssencmode": "disable",
        "connect_timeout": 5,
        "application_name": "sbom_w25_f047_write" if action == "unit_execute" else "sbom_w25_f047_readback",
        "options": "-c default_transaction_read_only=on -c statement_timeout=30000 -c lock_timeout=1000 -c idle_in_transaction_session_timeout=30000 -c row_security=on -c search_path=pg_catalog -c check_function_bodies=on -c stats_fetch_consistency=none",
    }


def create_meter(api, plan, action, allowlist, journal, clock=None):
    kwargs = {"journal": journal}
    if clock is not None:
        kwargs["clock"] = clock
    original = api["budget"]["scoped_meter"].create_meter(
        api["base"]["transport"].Meter,
        plan,
        "047_email_verification_tokens",
        action,
        allowlist,
        api["fresh"]["pg_lex"].statements,
        **kwargs,
    )
    strict = api["txn"]["metering"].wrap(type(original))

    class Meter(strict):
        def charge(self, key, count=1):
            require(
                action != "unit_readback" or key != "transaction_controls" or self.counts[key] + count <= 2,
                "Readback controls exhausted",
            )
            return super().charge(key, count)

    return Meter()


class Transport:
    """One connector, native properties then reviewed metered engine recipe."""

    def __init__(self, authority, meter, journal, *, connector, factories, resource_gate, correlate):
        self.authority, self.meter, self.journal = authority, meter, journal
        self.connector, self.factories, self.resource_gate, self.correlate = (
            connector,
            factories,
            resource_gate,
            correlate,
        )
        self.opened = False
        self.driver = self.session = None
        self.actual_attempts = 0

    def open(self):
        require(not self.opened, "No second connection")
        self.opened = True
        a = self.authority
        secret = None
        raw = None
        try:
            self.resource_gate()
            secret = self.correlate()
            a.recheck()
            self.resource_gate()
            a.recheck()
            self.meter.check()
            self.meter.charge("attempts")
            self.journal.record("CONNECT_REQUESTED", manifest_sha256=a.expected)
            self.actual_attempts += 1
            raw = self.connector(**connection_options(a.action), password=secret.decode("ascii"))
            require(
                raw.autocommit is False and a.api["txn"]["kernel"].status(raw) == "IDLE", "Unexpected connection state"
            )
            require(raw.pgconn.used_password is True, "Password use not established")
            raw.isolation_level = 2
            raw.read_only = True
            raw.prepare_threshold = None
            self.driver = a.api["txn"]["kernel"].Driver(raw, self.meter, self.journal)
            conn, engine = a.api["txn"]["recipe"].bind(self.driver, **self.factories)
            self.session = a.api["txn"]["kernel"].Session(conn, self.driver, engine, self.meter, self.journal)
            self.journal.record("CONNECTED", libpq_used_password=True, credential_correlated=True)
            return self.session
        except Exception as error:
            try:
                self.journal.record("FAILURE", **a.api["readonly"]["security"].safe_error(error, secret or b""))
            finally:
                if raw is not None:
                    raw.close()
            raise ValueError("Connection setup failed; see sanitized protected evidence") from None
        finally:
            if isinstance(secret, bytearray):
                secret[:] = b"\0" * len(secret)

    def close(self):
        if self.session is not None:
            self.session.close()
        elif self.driver is not None:
            self.driver.close()


def factories(api):
    # Called only after authority/source/dependency checks or by synthetic tests.
    import psycopg
    from psycopg.types import TypeInfo
    from sqlalchemy import text
    from sqlalchemy.dialects.postgresql.psycopg import PGDialect_psycopg
    from sqlalchemy.engine import Connection, Engine, make_url
    from sqlalchemy.pool import NullPool

    cls = api["txn"]["dialect"].factory(PGDialect_psycopg, text, TypeInfo)
    return {
        "dialect_factory": lambda: cls(dbapi=psycopg),
        "pool_factory": NullPool,
        "engine_factory": Engine,
        "url_factory": make_url,
        "connection_factory": Connection,
    }


def native_driver(api):
    import psycopg
    from w25_inputs import ROOT, unique

    pins = unique((ROOT / "infra/uuid-migration/f-readonly-acceptance/dependency-lock.json").read_bytes())["libpq"]
    require(
        {
            "implementation": psycopg.pq.__impl__,
            "version": psycopg.pq.version(),
            "used_password_api": hasattr(psycopg.pq.PGconn, "used_password"),
        }
        == pins,
        "Loaded native driver drift",
    )
    return psycopg
