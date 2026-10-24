"""W2.3 offline coordinator and mock transaction integration.

No live connector, Docker command, credential reader or application import.
Public simulation accepts Mock adapters only. --mode live always refuses.
"""

from __future__ import annotations

import argparse
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from authority import Authority, clean_environment, connection_contract, source_bundle
from isolated_loader import bind_mock, frozen_statements, mock_only
from observations import finalization_context, verify_database, verify_resources
from source_registry import discover, promotion_plan, reference_api, require

ADVISORY = "SELECT pg_catalog.pg_try_advisory_xact_lock(7160085085) AS acquired"
VERSION_LOCK = "LOCK TABLE ONLY public.alembic_version IN EXCLUSIVE MODE NOWAIT"
VERSION_SELECT = "SELECT version_num FROM public.alembic_version"
VERSION_CREATE = "CREATE TABLE public.alembic_version (version_num VARCHAR(128) NOT NULL PRIMARY KEY)"
VERSION_INSERT = "INSERT INTO public.alembic_version (version_num) VALUES (:revision) RETURNING version_num"
VERSION_UPDATE = (
    "UPDATE public.alembic_version SET version_num=:revision WHERE version_num=:previous RETURNING version_num"
)


@dataclass
class Meter:
    """Cooperative deadline; no hard network/COMMIT deadline is claimed."""

    limits: dict
    clock: object = time.monotonic
    sql_parser: object = None
    started: float | None = None
    counts: dict | None = None

    def __post_init__(self):
        self.started = self.clock()
        self.counts = {
            key: 0
            for key in (
                "attempts",
                "catalog_queries",
                "transaction_controls",
                "migration_statements",
                "marker_statements",
                "session_statements",
            )
        }

    def check(self):
        require(self.clock() - self.started < self.limits["cooperative_unit_seconds"], "Cooperative deadline exhausted")

    def charge(self, category, count=1):
        self.check()
        require(category in self.counts and type(count) is int and count > 0, "Unknown statement budget")
        require(
            self.counts[category] + count <= self.limits[category], "Unit statement/query/transaction budget exhausted"
        )
        self.counts[category] += count

    def before_cursor_execute(self, conn, cursor, statement, parameters, context, executemany):
        """Proposed SQLAlchemy driver-event meter; never attached in W2.3.

        Counts every driver execution, including reflection/seed SQL. Multiple
        parameter rows count toward the migration budget. No SQL is executed.
        """
        require(callable(self.sql_parser), "Reviewed SQL framer required for driver metering")
        framed = self.sql_parser(statement if statement.rstrip().endswith(";") else statement + ";")
        category = getattr(context, "execution_options", {}).get("w23_category", "migration_statements")
        require(
            category in {"migration_statements", "marker_statements", "session_statements"},
            "Unexpected driver budget classification",
        )
        rows = max(1, len(parameters)) if executemany else 1
        for part in framed:
            first = part.tokens[0].upper()
            require(
                first
                in {
                    "SELECT",
                    "SHOW",
                    "WITH",
                    "EXPLAIN",
                    "INSERT",
                    "UPDATE",
                    "DELETE",
                    "CREATE",
                    "ALTER",
                    "DROP",
                    "DO",
                    "SET",
                    "LOCK",
                    "COMMENT",
                },
                "Unreviewed driver SQL family/transaction control",
            )
            self.charge(category, rows)
            if first in {"SELECT", "SHOW", "WITH", "EXPLAIN"}:
                self.charge("catalog_queries", rows)


def safe_error(error):
    name = type(error).__name__
    state = getattr(error, "sqlstate", None)
    return {
        "exception": name if re.fullmatch("[A-Za-z_][A-Za-z_0-9]{0,79}", name) else "Error",
        "sqlstate": state if isinstance(state, str) and re.fullmatch("[A-Z0-9]{5}", state) else None,
        "reason": "REDACTED_REVIEW_REQUIRED",
    }


def _query(session, meter, sql, params=None):
    meter.charge("catalog_queries")
    return session.query(sql, params or {})


def _control(session, meter, name):
    meter.charge("transaction_controls")
    if name == "COMMIT":
        session.commit()
    elif name == "ROLLBACK":
        session.rollback()
    else:
        session.begin(name)


def _observe(backend, session, meter, authority, readonly, after=False):
    # Observer must charge every fixed/dynamic catalog query through this meter.
    # That interface is mocked only; actual observer/meter wiring is an explicit
    # activation gate, not a caller-provided accepted=True flag.
    raw = backend.observe(session, meter, authority.unit, readonly=readonly, after=after)
    return verify_database(
        authority.root, authority.registry, authority.plan, authority.unit, raw, readonly=readonly, after=after
    )


def _returned(result, expected):
    require(
        isinstance(result, dict)
        and set(result) == {"rowcount", "rows"}
        and result["rowcount"] == 1
        and type(result["rowcount"]) is int
        and result["rows"] == [{"version_num": expected}],
        "Marker rowcount/RETURNING mismatch",
    )


def simulate_write(authority, backend, *, run_unit=None, environment=None):
    """One MOCK connection, one owned write transaction. No live success value.

    Returns COMMITTED_UNVERIFIED after acknowledged mock commit and close. A
    separate action/entry phase is required for independent mock read-back.
    """
    mock_only(backend)
    require(
        isinstance(authority, Authority) and authority.args[2] == "unit_execute", "Exact execution authority required"
    )
    clean_environment({} if environment is None else environment)
    authority.recheck()
    meter = Meter(
        authority.unit["budgets"], sql_parser=reference_api(authority.root, authority.registry)["pg_lex"].statements
    )
    events = [authority.evidence()]
    session = None
    phase = "PRE_AUTH"
    tx_open = False
    outcome = "BLOCKED"
    failure = None
    rollback = None
    closed = False
    try:
        verify_resources(authority.plan, backend.resources())
        authority.recheck()  # Original bytes/source/expiry immediately pre-auth.
        meter.charge("attempts")
        session = backend.connect(
            connection_contract(authority.unit),
            credential_metadata=authority.plan["credential_metadata"],
            environment={},
        )
        mock_only(session)
        require(session.autocommit is False, "Autocommit forbidden")
        phase = "READ_ONLY_PREFLIGHT"
        _control(session, meter, "BEGIN READ ONLY")
        tx_open = True
        _observe(backend, session, meter, authority, True)
        _control(session, meter, "ROLLBACK")
        tx_open = False
        authority.recheck()
        _control(session, meter, "BEGIN READ WRITE")
        tx_open = True
        phase = "INSTALLING"
        require(_query(session, meter, ADVISORY) == [{"acquired": True}], "Serialization lock unavailable")
        if authority.unit["previous"] is not None:
            meter.charge("catalog_queries")
            session.lock(VERSION_LOCK)
            require(
                _query(session, meter, VERSION_SELECT) == [{"version_num": authority.unit["previous"]}],
                "Wrong sole predecessor marker",
            )
        verify_resources(authority.plan, backend.resources())
        verified = _observe(backend, session, meter, authority, False)
        for name in verified.table_names:
            quoted = 'public."' + name.replace('"', '""') + '"'
            meter.charge("catalog_queries")
            session.lock(f"LOCK TABLE ONLY {quoted} IN SHARE MODE NOWAIT")
        authority.recheck()  # Authority/source/catalog/roles under serialization.
        context = SimpleNamespace(
            as_sql=False,
            dialect=SimpleNamespace(name="postgresql"),
            impl=SimpleNamespace(transactional_ddl=True),
            opts={},
        )
        if authority.unit["kind"] == "uuid_finalize":
            context.opts["w22_f_finalization"] = finalization_context(authority, verified)
        if authority.unit["kind"] == "historical":
            require(
                session.dialect.default_schema_name == "public",
                "Dedicated historical dialect must bind default schema public",
            )
            meter.charge("session_statements")
            session.execute("SET LOCAL search_path = public, pg_catalog", {})
        if authority.unit["kind"] == "frozen_047":
            statements = frozen_statements(authority.root, authority.registry)
            for statement in statements:
                meter.charge("migration_statements")
                session.execute(statement, {})
            events.append({"schema_statements_acknowledged": len(statements)})
            meter.charge("marker_statements")
            session.execute(VERSION_CREATE, {})
        else:
            operations = backend.operations(session, context, meter)
            mock_only(operations)
            operations.get_bind.return_value = session
            operations.get_context.return_value = context
            binding = bind_mock(authority.root, authority.registry, authority.unit, operations, context)
            authority.recheck()
            if run_unit is None:
                binding.upgrade()
            else:
                # Only a Mock callback is admitted; never a generic live bypass.
                mock_only(run_unit)
                run_unit(binding, operations, context, meter)
            events.append({"selected_revision_body": authority.unit["next"]})
        if authority.unit["kind"] in {"frozen_047", "historical"}:
            meter.charge("session_statements")
            session.execute("SET LOCAL search_path = pg_catalog", {})
        # Verify schema/security/reference expected outcome before changing the
        # marker, while retaining the old marker until this exact point.
        authority.recheck()
        backend.precommit(session, meter, authority.unit)
        # Raw observations must prove the expected post catalog and old marker;
        # post verification expects new marker, so validate a copy with the one
        # planned marker only after separately checking actual old state.
        raw = backend.observe(session, meter, authority.unit, readonly=False, after=True)
        require(
            raw["marker"] == ([] if authority.unit["previous"] is None else [authority.unit["previous"]]),
            "Marker changed during migration body",
        )
        raw = {**raw, "marker": [authority.unit["next"]]}
        verify_database(
            authority.root, authority.registry, authority.plan, authority.unit, raw, readonly=False, after=True
        )
        authority.recheck()
        if authority.unit["previous"] is None:
            sql, params = VERSION_INSERT, {"revision": authority.unit["next"]}
        else:
            sql, params = VERSION_UPDATE, {"previous": authority.unit["previous"], "revision": authority.unit["next"]}
        meter.charge("marker_statements")
        _returned(session.marker(sql, params), authority.unit["next"])
        require(
            _query(session, meter, VERSION_SELECT) == [{"version_num": authority.unit["next"]}],
            "Extra/wrong marker rows after update",
        )
        phase = "PRECOMMIT_VERIFIED"
        events.append({"phase": phase})
        meter.check()
        meter.charge("transaction_controls")
        phase = "COMMIT_REQUESTED"
        session.commit()
        tx_open = False
        phase = "COMMIT_ACKNOWLEDGED"
        outcome = "COMMITTED_UNVERIFIED"
        events.append({"phase": phase})
    except Exception as error:
        failure = safe_error(error)
        if phase == "COMMIT_REQUESTED":
            outcome = "UNKNOWN_COMMIT_STOP_MANUAL_RECONCILIATION"
        elif phase == "COMMIT_ACKNOWLEDGED":
            outcome = "COMMITTED_UNVERIFIED"
        elif tx_open:
            try:
                # Cleanup remains mandatory after deadline; no new mutation or
                # query is admitted. It still consumes a control budget slot.
                require(
                    meter.counts["transaction_controls"] < meter.limits["transaction_controls"], "No rollback budget"
                )
                meter.counts["transaction_controls"] += 1
                session.rollback()
                rollback = "ACKNOWLEDGED"
                tx_open = False
                outcome = "ROLLED_BACK_UNVERIFIED"
            except Exception as cleanup:
                rollback = safe_error(cleanup)
                outcome = "UNKNOWN_ROLLBACK_STOP_MANUAL_RECONCILIATION"
    finally:
        if session is not None:
            try:
                session.close()
                closed = session.closed is True
            except Exception as cleanup:
                events.append({"close_error": safe_error(cleanup)})
            if not closed and outcome == "COMMITTED_UNVERIFIED":
                outcome = "COMMITTED_CLOSE_UNVERIFIED"
    return {
        "mode": "MOCK_ONLY",
        "outcome": outcome,
        "phase": phase,
        "commit_acknowledged": phase == "COMMIT_ACKNOWLEDGED",
        "closed": closed,
        "rollback": rollback,
        "failure": failure,
        "counts": meter.counts,
        "events": events,
        "unit": authority.unit["next"],
        "manifest_sha256": authority.approved_hash,
        "post_sha256": authority.plan["post_sha256"],
        "identity": authority.plan["identity"],
    }


def simulate_validate(authority, backend):
    """Separately approved bounded READ ONLY rehearsal, MOCK ONLY."""
    mock_only(backend)
    require(
        isinstance(authority, Authority) and authority.args[2] == "unit_validate",
        "Distinct validation approval required",
    )
    authority.recheck()
    meter = Meter(
        authority.unit["budgets"], sql_parser=reference_api(authority.root, authority.registry)["pg_lex"].statements
    )
    session = None
    failure = None
    closed = False
    rollback = False
    observed = False
    try:
        verify_resources(authority.plan, backend.resources())
        authority.recheck()
        meter.charge("attempts")
        session = backend.connect(
            connection_contract(authority.unit),
            credential_metadata=authority.plan["credential_metadata"],
            environment={},
        )
        mock_only(session)
        require(session.autocommit is False, "Autocommit forbidden")
        _control(session, meter, "BEGIN READ ONLY")
        _observe(backend, session, meter, authority, True)
        authority.recheck()
        observed = True
    except Exception as error:
        failure = safe_error(error)
    finally:
        if session is not None:
            try:
                meter.counts["transaction_controls"] += 1
                session.rollback()
                rollback = True
            except Exception as error:
                failure = safe_error(error)
            try:
                session.close()
                closed = session.closed is True
            except Exception as error:
                failure = safe_error(error)
    return {
        "mode": "MOCK_ONLY",
        "outcome": "MOCK_VALIDATED"
        if observed and rollback and closed and failure is None
        else "VALIDATION_FAILED_STOP",
        "observed": observed,
        "rollback": rollback,
        "closed": closed,
        "failure": failure,
        "events": [authority.evidence()],
    }


def simulate_readback(authority, backend, write_receipt):
    """Separately approved one-connection independent read-back, MOCK ONLY."""
    mock_only(backend)
    require(
        isinstance(authority, Authority) and authority.args[2] == "unit_readback",
        "Separate read-back approval required",
    )
    require(
        write_receipt["mode"] == "MOCK_ONLY"
        and write_receipt["outcome"] == "COMMITTED_UNVERIFIED"
        and write_receipt["commit_acknowledged"] is True
        and write_receipt["closed"] is True
        and write_receipt["unit"] == authority.unit["next"]
        and write_receipt["post_sha256"] == authority.plan["post_sha256"]
        and write_receipt["identity"] == authority.plan["identity"],
        "Commit/closure/identity requires independent reconciliation",
    )
    authority.recheck()
    meter = Meter(
        authority.unit["budgets"], sql_parser=reference_api(authority.root, authority.registry)["pg_lex"].statements
    )
    session = None
    failure = None
    closed = False
    rollback = False
    observed = False
    try:
        verify_resources(authority.plan, backend.resources())
        authority.recheck()
        meter.charge("attempts")
        session = backend.connect(
            connection_contract(authority.unit, readback=True),
            credential_metadata=authority.plan["credential_metadata"],
            environment={},
        )
        mock_only(session)
        require(session.autocommit is False, "Autocommit forbidden")
        _control(session, meter, "BEGIN READ ONLY")
        _observe(backend, session, meter, authority, True, True)
        authority.recheck()
        observed = True
    except Exception as error:
        failure = safe_error(error)
    finally:
        if session is not None:
            try:
                meter.counts["transaction_controls"] += 1
                session.rollback()
                rollback = True
            except Exception as error:
                failure = safe_error(error)
            try:
                session.close()
                closed = session.closed is True
            except Exception as error:
                failure = safe_error(error)
    return {
        "mode": "MOCK_ONLY",
        "outcome": "MOCK_ACCEPTED" if observed and rollback and closed and failure is None else "READBACK_FAILED_STOP",
        "observed": observed,
        "rollback": rollback,
        "closed": closed,
        "failure": failure,
        "events": [authority.evidence()],
    }


def inspect_offline(root):
    registry = discover(root)
    refs = reference_api(root, registry)
    require(len(frozen_statements(root, registry)) == 558, "Frozen047 changed")
    return {
        "mode": "OFFLINE_ONLY",
        "active_head": "079_lifecycle_provider_verification",
        "combined_head": registry["graph"][-1]["revision"],
        "units": registry["units"],
        "source_sha256": source_bundle(root, registry),
        "promotion_proposal": promotion_plan(registry),
        "reference_acceptance": refs["fresh_bootstrap"].reference_contract(root, registry["lock"]["sources"]),
        "postgresql_connections": 0,
        "live_mode": "DENIED_PENDING_SOURCE_SPECIFIC_ACTIVATION",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("offline", "live"), default="offline")
    args = parser.parse_args(argv)
    if args.mode == "live":
        parser.exit(2, "W2.3 live execution is denied pending separately reviewed source-specific activation.\n")
    print(json.dumps(inspect_offline(Path(__file__).resolve().parents[3]), sort_keys=True))


if __name__ == "__main__":
    main()
