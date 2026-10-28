"""One frozen047 unit, commit stops unaccepted until separately approved readback."""

from __future__ import annotations

import w25_catalog as catalog
from w25_inputs import digest, require
from w25_schema import ADVISORY, CREATE_MARKER, INSERT_MARKER, MARKER, MARKER_SQL, RESET


def schema_digest(data):
    keys = (
        "relations",
        "columns",
        "types",
        "schemas",
        "schema_privileges",
        "constraints",
        "indexes",
        "sequences",
        "sequence_ownership",
        "storage",
        "roles",
        "memberships",
        "extensions",
        "default_acl",
    )
    return digest({k: sorted(data[k], key=digest) for k in keys})


def record_observations(journal, phase, data):
    # Persist only AFTER complete validation: no unexpected application rows,
    # function configuration or secret-like metadata is accepted/logged.
    for key, value in data.items():
        journal.record("CATALOG_OBSERVATION", phase=phase, category=key, rows=value)


def write(authority, transport, meter, journal, representation):
    session = None
    outcome = "BLOCKED"
    error = None
    raw_closed = False
    resources = False
    post_digest = None
    body_acks = 0
    try:
        require(authority.action == "unit_execute", "Write action required")
        authority.recheck()
        transport.resource_gate()
        session = transport.open()
        session.begin("ro")
        session.initialize(authority.api["txn"]["recipe"].initializer)
        require(session.connection.dialect.server_version_info[:2] == (16, 15), "Dialect server version mismatch")
        with meter.phase("preflight"):
            data = catalog.collect(session.connection, authority.api, meter, representation["model"], after=False)
            catalog.verify(
                data, authority.baseline, authority.api, representation["model"], readonly=True, after=False, marker=[]
            )
        record_observations(journal, "preflight", data)
        journal.record("PREFLIGHT_ACCEPTED", catalog_sha256=digest(data))
        session.finish_readonly()
        authority.recheck()
        session.begin("rw")
        with meter.phase("coordinator"):
            require(
                catalog.rows(session.connection, ADVISORY, meter=meter) == [{"acquired": True}],
                "Advisory lock unavailable",
            )
        authority.recheck()
        transport.resource_gate()
        with meter.phase("locked_reinspection"):
            data = catalog.collect(session.connection, authority.api, meter, representation["model"], after=False)
            catalog.verify(
                data, authority.baseline, authority.api, representation["model"], readonly=False, after=False, marker=[]
            )
        record_observations(journal, "locked_reinspection", data)
        journal.record("LOCKED", catalog_sha256=digest(data))
        authority.recheck()
        journal.record("BODY_REQUESTED", execution_sha256=representation["execution_sha256"])
        with meter.phase("body"), meter.scope("migration_statements"):
            for sql in representation["statements"]:
                authority.check_window()
                meter.check()
                session.connection.exec_driver_sql(sql)
                body_acks += 1
        require(body_acks == 558, "Incomplete schema body")
        journal.record("BODY_ACKNOWLEDGED", statements=body_acks)
        authority.recheck()
        # Newly created marker table is private to this owned transaction; CREATE
        # holds ACCESS EXCLUSIVE until commit. No pre-existing version table or
        # tables exist to lock. Advisory7160085085 was acquired before all DDL.
        with meter.scope("marker_statements"):
            session.connection.exec_driver_sql(CREATE_MARKER)
        with meter.scope("session_statements"):
            session.connection.exec_driver_sql(RESET)
        authority.recheck()
        with meter.phase("post_body"):
            data = catalog.collect(session.connection, authority.api, meter, representation["model"], after=True)
            catalog.verify(
                data, authority.baseline, authority.api, representation["model"], readonly=False, after=True, marker=[]
            )
        post_digest = schema_digest(data)
        record_observations(journal, "post_body", data)
        journal.record("POST_SCHEMA_ACCEPTED", catalog_sha256=post_digest, model_sha256=representation["model_sha256"])
        authority.recheck()
        with meter.scope("marker_statements"):
            result = session.connection.exec_driver_sql(INSERT_MARKER, {"revision": MARKER})
            require(
                type(result.rowcount) is int
                and result.rowcount == 1
                and [dict(x) for x in result.mappings().all()] == [{"version_num": MARKER}],
                "Marker rowcount/RETURNING mismatch",
            )
        with meter.phase("coordinator"):
            require(
                catalog.rows(session.connection, MARKER_SQL, meter=meter) == [{"version_num": MARKER}],
                "Wrong sole marker",
            )
        journal.record("MARKER_ACKNOWLEDGED", revision=MARKER)
        authority.recheck()
        transport.resource_gate()
        meter.check()
        journal.record("COMMIT_REQUESTED")
        session.end("commit")
        outcome = "COMMITTED_UNVERIFIED"
    except Exception as exc:
        error = authority.api["readonly"]["security"].safe_error(exc)
        if session is not None and session.driver.commit_ack:
            outcome = "COMMITTED_EVIDENCE_INCOMPLETE"
        elif session is not None and session.driver.commit_sent:
            outcome = "UNKNOWN_COMMIT_MANUAL_RECONCILIATION"
        elif session is not None:
            try:
                if (
                    authority.api["txn"]["kernel"].status(session.driver.raw) == "IDLE"
                    and not session.driver.attempted_begin
                    and not meter.transaction_open
                ):
                    outcome = "BLOCKED_NO_TRANSACTION"
                else:
                    session.cleanup()
                    require(
                        authority.api["txn"]["kernel"].status(session.driver.raw) == "IDLE"
                        and session.driver.owner is None,
                        "Rollback not established",
                    )
                    outcome = "ROLLED_BACK_UNVERIFIED"
            except Exception:
                outcome = "ROLLBACK_UNCONFIRMED_MANUAL_RECONCILIATION"
        try:
            journal.record("FAILURE", **error)
        except Exception:
            pass
    finally:
        try:
            transport.close()
            raw_closed = session is not None and bool(session.driver.raw.closed)
            journal.record("CLOSED", physical_closed=raw_closed)
            journal.record("DISPOSED")
        except Exception:
            raw_closed = session is not None and bool(session.driver.raw.closed)
            outcome += "_CLOSURE_INCOMPLETE"
        try:
            transport.resource_gate()
            resources = True
            journal.record("RESOURCES_PRESERVED")
        except Exception:
            outcome += "_RESOURCES_INCOMPLETE"
    result = {
        "accepted": False,
        "outcome": outcome,
        "body_statements_acknowledged": body_acks,
        "commit_sent": session is not None and session.driver.commit_sent,
        "commit_acknowledged": session is not None and session.driver.commit_ack,
        "physical_closed": raw_closed,
        "logical_cleanup_and_disposal": session is not None and session.closed,
        "resources_preserved": resources,
        "schema_sha256": post_digest,
        "model_sha256": representation["model_sha256"],
        "attempts": transport.actual_attempts,
        "counts": dict(meter.counts),
        "phase_counts": dict(meter.phase_counts),
        "failure": error,
        "readback_required": True,
    }
    try:
        journal.record("STOP", result=result)
    except Exception:
        result["outcome"] += "_EVIDENCE_INCOMPLETE"
    return result


def verify_write_evidence(authority):
    ref = authority.plan["write_evidence"]
    require(type(ref) is dict, "Approved original write evidence required")
    raw = authority.api["readonly"]["security"].private_bytes(ref["path"], ref["sha256"])
    previous = "0" * 64
    events = []
    require(raw.endswith(b"\n"), "Incomplete write evidence frame")
    from w25_inputs import sha, unique

    for line in raw.splitlines(keepends=True):
        row = unique(line)
        require(row["previous_sha256"] == previous, "Broken write chain")
        previous = sha(line)
        events.append(row)
    require(events and events[0]["event"] == "CLAIMED" and events[-1]["event"] == "STOP", "Incomplete write chain")
    stop = events[-1]["result"]
    require(
        stop["outcome"] == "COMMITTED_UNVERIFIED"
        and stop["commit_acknowledged"] is True
        and stop["physical_closed"] is True
        and stop["logical_cleanup_and_disposal"] is True
        and stop["resources_preserved"] is True
        and stop["body_statements_acknowledged"] == 558
        and stop["model_sha256"] == authority.plan["model_sha256"],
        "Unaccepted write disposition",
    )
    require(
        sum(r["event"] == "COMMIT_ACKNOWLEDGED" for r in events) == 1
        and sum(r["event"] == "MARKER_ACKNOWLEDGED" for r in events) == 1,
        "Missing/duplicate commit/marker evidence",
    )
    proofs = [r for r in events if r["event"] == "AUTHORITY"]
    require(
        len(proofs) == 1
        and proofs[0]["unit"] == MARKER
        and proofs[0]["action"] == "unit_execute"
        and proofs[0]["sources_lock_sha256"] == authority.plan["sources_lock_sha256"],
        "Wrong write provenance",
    )
    require(
        sum(r["event"] == "CONNECT_REQUESTED" for r in events) == 1
        and sum(r["event"] == "CONNECTED" for r in events) == 1
        and stop["attempts"] == 1
        and stop["counts"]["migration_statements"] == 558
        and stop["counts"]["marker_statements"] == 2,
        "Wrong one-unit execution evidence",
    )
    require(not any(r["event"] == "FAILURE" for r in events), "Failed write evidence cannot authorize readback")
    from w25_inputs import FOLDER

    expected_sql = unique((FOLDER / "sql-allowlist.w25.json").read_bytes())["templates"]
    for category, expected in [
        ("migration_statements", expected_sql["migration"]),
        ("marker_statements", expected_sql["marker"]),
    ]:
        actual = [r for r in events if r["event"] == "SQL_REQUESTED" and r["category"] == category]
        require(
            [r["sql_sha256"] for r in actual] == [sha(s.encode()) for s in expected]
            and all(r["count"] == 1 for r in actual),
            "Incomplete/changed ordered driver execution proof",
        )
    proof = proofs[0]
    original = authority.api["readonly"]["security"].private_bytes(proof["manifest_path"], proof["manifest_sha256"])
    from datetime import datetime

    from w25_contract import validate

    original_plan = unique(original)
    commit_time = next(r["utc"] for r in events if r["event"] == "COMMIT_ACKNOWLEDGED")
    validate(
        original_plan,
        authority.api,
        action="unit_execute",
        reference=original_plan["approvals"].get("unit_execute"),
        live=True,
        now=datetime.fromisoformat(commit_time),
    )
    model = unique((FOLDER / "expected-schema.w25.json").read_bytes())["model"]
    snapshots = {phase: {} for phase in ["preflight", "locked_reinspection", "post_body"]}
    for row in events:
        if row["event"] == "CATALOG_OBSERVATION":
            require(
                row["phase"] in snapshots and row["category"] not in snapshots[row["phase"]],
                "Duplicate/unapproved catalog receipt",
            )
            snapshots[row["phase"]][row["category"]] = row["rows"]
    for phase, data in snapshots.items():
        catalog.verify(
            data,
            authority.baseline,
            authority.api,
            model,
            readonly=phase == "preflight",
            after=phase == "post_body",
            marker=[],
        )
    require(
        schema_digest(snapshots["post_body"]) == stop["schema_sha256"],
        "Write catalog fingerprint differs from saved observations",
    )
    return stop["schema_sha256"]


def readback(authority, transport, meter, journal, representation):
    require(authority.action == "unit_readback", "Separate readback authority required")
    session = None
    accepted = False
    error = None
    fingerprint = None
    resources = False
    try:
        write_hash = verify_write_evidence(authority)
        authority.recheck()
        transport.resource_gate()
        session = transport.open()
        session.begin("ro")
        session.initialize(authority.api["txn"]["recipe"].initializer)
        with meter.phase("readback"):
            data = catalog.collect(session.connection, authority.api, meter, representation["model"], after=True)
            catalog.verify(
                data,
                authority.baseline,
                authority.api,
                representation["model"],
                readonly=True,
                after=True,
                marker=[{"version_num": MARKER}],
            )
        fingerprint = schema_digest(data)
        require(fingerprint == write_hash, "Committed schema differs from acknowledged write")
        record_observations(journal, "readback", data)
        authority.recheck()
        session.finish_readonly()
        accepted = True
    except Exception as exc:
        error = authority.api["readonly"]["security"].safe_error(exc)
        if session is not None:
            try:
                session.cleanup()
            except Exception:
                accepted = False
    finally:
        try:
            transport.close()
            require(session is not None and session.closed, "Readback closure incomplete")
            journal.record("CLOSED", physical_closed=True)
            journal.record("DISPOSED")
        except Exception:
            accepted = False
        try:
            transport.resource_gate()
            resources = True
            journal.record("RESOURCES_PRESERVED")
        except Exception:
            accepted = False
    result = {
        "accepted": bool(accepted and resources),
        "outcome": "FROZEN047_INDEPENDENTLY_ACCEPTED" if accepted and resources else "READBACK_BLOCKED_OR_INCOMPLETE",
        "schema_sha256": fingerprint,
        "actual_marker": MARKER if accepted else None,
        "physical_closed": session is not None and bool(session.driver.raw.closed),
        "logical_cleanup_and_disposal": session is not None and session.closed,
        "rollback_acknowledged": session is not None and session.driver.rollback_ack,
        "resources_preserved": resources,
        "attempts": transport.actual_attempts,
        "counts": dict(meter.counts),
        "phase_counts": dict(meter.phase_counts),
        "failure": error,
    }
    journal.record("STOP", result=result)
    return result
