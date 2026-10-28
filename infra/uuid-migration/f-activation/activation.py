"""Staged F-only lifecycle. CLI live mode is unconditionally unavailable.

No built-in connector/resource/credential provider, worker spawn, Docker command,
engine factory or activated execution plan exists. All integration calls in this
stage use injected offline mocks. Source-specific live activation needs review.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import binding
import catalog
from journal import safe_error
from reviewed import load

from security import require


def sql(connection, meter, text_factory, statement, params=None, category="migration_statements"):
    with meter.scope(category):
        return connection.execute(text_factory(statement), params or {})


def control(connection, meter, statement):
    # The DBAPI cursor boundary owns the one control charge, not this wrapper.
    with meter.owned_control():
        connection.exec_driver_sql(statement)


def observe(authority, connection, meter, text_factory, *, after=False, readonly=True):
    raw = catalog.collect(authority, connection, meter, text_factory, after=after)
    token = catalog.verify(authority, raw, readonly=readonly, after=after)
    return raw, token


def marker_rows(result, expected):
    require(
        result.rowcount == 1
        and type(result.rowcount) is int
        and [dict(r) for r in result.mappings().all()] == [{"version_num": expected}],
        "Marker RETURNING mismatch",
    )


def stage_unit(
    authority, transport, meter, journal, *, resource_gate, text_factory, context_factory, operations_factory
):
    """Future injected one-unit path, never called by CLI or supplied real IO here.

    resource_gate must refresh actual resources/correlation and erase any extra
    correlated bytes; a dict/accepted flag is insufficient. Authority's separate
    effective-auth artifact must already be independently reviewed. Journal must
    claim a private per-unit directory before this function is entered.
    """
    connection = None
    outcome, failure = "BLOCKED", None
    commit_ack = False
    try:
        authority.recheck()
        ua = authority.unit_authority
        require(ua.args[2] == "unit_execute", "Separate execute approval required")
        require(transport.options == authority.plan["connection"], "Transport differs from approved options")
        resource_gate(authority)
        authority.recheck()  # original bytes/source/dependency/expiry immediately before authentication
        journal.record("CONNECT_REQUESTED")
        connection = transport.open()
        journal.record("CONNECTED")
        control(connection, meter, "BEGIN READ ONLY")
        _, verified = observe(authority, connection, meter, text_factory)
        journal.record("PREFLIGHT_ACCEPTED")
        control(connection, meter, "ROLLBACK")
        control(connection, meter, "BEGIN READ WRITE")
        require(
            catalog.query(connection, meter, text_factory, catalog.ADVISORY) == [{"acquired": True}],
            "Advisory lock unavailable",
        )
        if ua.unit["previous"] is not None:
            sql(connection, meter, text_factory, catalog.VERSION_LOCK)
        for name in verified.table_names:
            sql(connection, meter, text_factory, "LOCK TABLE ONLY " + catalog.relation(name) + " IN SHARE MODE NOWAIT")
        resource_gate(authority)
        authority.recheck()
        _, verified = observe(authority, connection, meter, text_factory, readonly=False)
        journal.record("LOCKED")
        opts = {}
        if ua.unit["kind"] == "uuid_finalize":
            opts["w22_f_finalization"] = authority.modules["observations"].finalization_context(ua, verified)
        # This engine/dialect is dedicated. Never patch a shared app dialect.
        require(connection.dialect.name == "postgresql", "Wrong SQL dialect")
        connection.dialect.default_schema_name = "public"
        if ua.unit["kind"] == "historical":
            sql(
                connection,
                meter,
                text_factory,
                "SET LOCAL search_path = public, pg_catalog",
                category="session_statements",
            )
        if ua.unit["kind"] == "frozen_047":
            body = authority.modules["isolated_loader"].frozen_statements(authority.root, authority.registry)
            require(len(body) == 558, "Incomplete frozen representation")
            authority.recheck()
            journal.record("BODY_REQUESTED")
            for statement in body:
                sql(connection, meter, text_factory, statement)
            sql(connection, meter, text_factory, catalog.VERSION_CREATE, category="marker_statements")
        else:
            context, op = binding.operations(
                connection, context_factory=context_factory, operations_factory=operations_factory, opts=opts
            )
            upgrade = binding.bind(authority, op, context)
            authority.recheck()
            journal.record("BODY_REQUESTED")
            with meter.scope("migration_statements"):
                upgrade()
        journal.record("BODY_ACKNOWLEDGED")
        if ua.unit["kind"] in {"frozen_047", "historical"}:
            sql(connection, meter, text_factory, "SET LOCAL search_path = pg_catalog", category="session_statements")
        authority.recheck()
        raw = catalog.collect(authority, connection, meter, text_factory, after=True)
        require(
            raw["marker"] == ([] if ua.unit["previous"] is None else [ua.unit["previous"]]),
            "Migration body changed the version marker",
        )
        # A planning-only copy checks post-schema before the guarded version DML;
        # actual marker remains separately observed and checked above/below.
        catalog.verify(authority, {**raw, "marker": [ua.unit["next"]]}, readonly=False, after=True)
        authority.recheck()
        values = {"revision": ua.unit["next"]}
        if ua.unit["previous"] is not None:
            values["previous"] = ua.unit["previous"]
        result = sql(
            connection,
            meter,
            text_factory,
            catalog.INSERT if ua.unit["previous"] is None else catalog.UPDATE,
            values,
            "marker_statements",
        )
        marker_rows(result, ua.unit["next"])
        require(
            catalog.query(connection, meter, text_factory, catalog.MARKER) == [{"version_num": ua.unit["next"]}],
            "Extra/wrong marker after DML",
        )
        journal.record("MARKER_ACKNOWLEDGED")
        authority.recheck()
        meter.check()
        journal.record("COMMIT_REQUESTED")  # fsync failure here prevents COMMIT
        control(connection, meter, "COMMIT")
        commit_ack = True
        outcome = "COMMITTED_UNVERIFIED"
        journal.record("COMMIT_ACKNOWLEDGED")
    except Exception as error:
        failure = safe_error(error)
        if commit_ack or meter.commit_ack:
            outcome = "COMMITTED_EVIDENCE_INCOMPLETE"
        elif meter.commit_sent:
            outcome = "UNKNOWN_COMMIT_MANUAL_RECONCILIATION"
        elif connection is not None and meter.transaction_open:
            try:
                meter.cleanup = True
                control(connection, meter, "ROLLBACK")
                outcome = "ROLLED_BACK_UNVERIFIED"
                try:
                    journal.record("ROLLBACK_ACKNOWLEDGED")
                except Exception:
                    outcome = "ROLLED_BACK_EVIDENCE_INCOMPLETE"
            except Exception:
                outcome = "UNKNOWN_ROLLBACK_MANUAL_RECONCILIATION"
    finally:
        try:
            transport.close()
            journal.record("CLOSED")
            journal.record("DISPOSED")
        except Exception:
            outcome += "_CLOSURE_OR_EVIDENCE_INCOMPLETE"
        try:
            journal.record("STOP", outcome=outcome, **(failure or {}))
        except Exception:
            if "INCOMPLETE" not in outcome:
                outcome += "_EVIDENCE_INCOMPLETE"
        journal.close()
    return {
        "outcome": outcome,
        "commit_acknowledged": commit_ack or meter.commit_ack,
        "failure": failure,
        "counts": dict(meter.counts),
        "accepted": False,
    }


def stage_readonly(authority, transport, meter, journal, *, resource_gate, text_factory, after=False):
    """Distinct validate/readback authority, one new RO connection; never executes a unit.

    Readback establishes observed state, not historical execution provenance.
    Durable write evidence must be independently reconciled before acceptance.
    """
    require(
        authority.unit_authority.args[2] == ("unit_readback" if after else "unit_validate"),
        "Separate read-only action required",
    )
    connection = None
    result = {"accepted": False, "outcome": "BLOCKED"}
    try:
        authority.recheck()
        require(transport.options == authority.plan["connection"], "Unapproved read-only transport")
        resource_gate(authority)
        authority.recheck()
        journal.record("CONNECT_REQUESTED")
        connection = transport.open()
        journal.record("CONNECTED")
        control(connection, meter, "BEGIN READ ONLY")
        _, verified = observe(authority, connection, meter, text_factory, after=after)
        authority.recheck()
        resource_gate(authority)
        control(connection, meter, "ROLLBACK")
        journal.record("ROLLBACK_ACKNOWLEDGED")
        result = {
            "accepted": False,
            "outcome": "READBACK_OBSERVED" if after else "VALIDATION_OBSERVED",
            "catalog_sha256": verified.prefix,
        }
        journal.record("READBACK_ACCEPTED" if after else "PREFLIGHT_ACCEPTED")
    except Exception as error:
        result["failure"] = safe_error(error)
        if connection is not None and meter.transaction_open:
            try:
                meter.cleanup = True
                control(connection, meter, "ROLLBACK")
            except Exception:
                result["outcome"] = "UNKNOWN_ROLLBACK_MANUAL_RECONCILIATION"
    finally:
        try:
            transport.close()
            journal.record("CLOSED")
            journal.record("DISPOSED")
        except Exception:
            result["outcome"] = "CLOSURE_OR_EVIDENCE_INCOMPLETE"
        journal.close()
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["offline", "live"], required=True)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[3])
    args = parser.parse_args(argv)
    if args.mode == "live":
        parser.exit(2, "W2.4A live activation is NOT APPROVED; no connector/provider is wired.\n")
    modules, registry = load(args.root)
    frozen = modules["isolated_loader"].frozen_statements(args.root, registry)
    print(
        json.dumps(
            {
                "mode": "offline",
                "pins": len(registry["lock"]["sources"]),
                "graph": len(registry["graph"]),
                "units": len(registry["units"]),
                "frozen_statements": len(frozen),
                "live_enabled": False,
                "accepted": False,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
