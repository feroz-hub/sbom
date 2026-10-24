"""Dependency-injected correction proposal; CLI cannot construct a live path."""

from __future__ import annotations

import argparse

from kernel import require


def stage(session, authority, journal, *, initialize, preflight, locks, locked, body, post_body, marker):
    """Callbacks are proposed execution-copy integration, never manifest receipts.

    authority retains raw-manifest/source/F-resource/secret/security checks;
    observations must run actual pinned collectors/verifiers, with prefix checks.
    No internal readback/second connection: separate unit_readback authority only.
    """
    outcome = "BLOCKED"
    error_class = None
    try:
        authority.recheck()
        session.begin("ro")
        session.initialize(initialize)
        with session.meter.phase("preflight"):
            preflight(session.connection)  # exact predecessor, full accepted prefix, transaction_read_only=on
        journal.record("PREFLIGHT_ACCEPTED")
        session.finish_readonly()
        authority.recheck()
        session.begin("rw")
        with session.meter.phase("coordinator"):
            locks(session.connection)  # first SELECT acquires advisory; exact version/table locks follow
        authority.recheck()
        with session.meter.phase("locked_reinspection"):
            locked(session.connection)  # independently recheck RW, source/target/roles/catalog/writers
        journal.record("LOCKED")
        authority.recheck()
        with session.meter.phase("body"), session.meter.scope("migration_statements"):
            body(session.connection)  # exactly one frozen558 or pinned isolated Operations upgrade
        journal.record("BODY_ACKNOWLEDGED")
        with session.meter.phase("post_body"):
            post_body(session.connection)  # actual old marker, exact expected schema delta
        authority.recheck()
        with session.meter.phase("coordinator"):
            marker(session.connection)  # parameterized next-only RETURNING + sole-marker SELECT
        journal.record("MARKER_ACKNOWLEDGED")
        authority.recheck()
        session.meter.check()
        journal.record("COMMIT_REQUESTED")
        session.end("commit")
        outcome = "COMMITTED_UNVERIFIED"
    except Exception as exc:
        error_class = type(exc).__name__  # no exception arguments, DSN or SQL parameters
        if session.driver.commit_ack:
            outcome = "COMMITTED_EVIDENCE_INCOMPLETE"
        elif session.driver.commit_sent:
            outcome = "UNKNOWN_COMMIT_MANUAL_RECONCILIATION"
        else:
            try:
                session.cleanup()
                outcome = "ROLLED_BACK_UNVERIFIED" if session.driver.rollback_ack else "BLOCKED"
            except Exception:
                outcome = "ROLLBACK_UNCONFIRMED_MANUAL_RECONCILIATION"
    finally:
        try:
            session.close()
            journal.record("CLOSED")
            journal.record("DISPOSED")
        except Exception:
            outcome += "_CLOSURE_INCOMPLETE"
        try:
            journal.record("STOP", outcome=outcome)
        except Exception:
            outcome += "_EVIDENCE_INCOMPLETE"
    return {"accepted": False, "outcome": outcome, "error_class": error_class, "closed": session.closed}


def read_only(session, authority, journal, *, initialize, observe):
    """Separately authorized validation/readback, its OWN W2.4B action budget."""
    require(authority.action in {"unit_validate", "unit_readback"}, "Separate readonly action required")
    try:
        authority.recheck()
        session.begin("ro")
        session.initialize(initialize)
        with session.meter.phase("readback" if authority.action == "unit_readback" else "preflight"):
            result = observe(session.connection)
        session.finish_readonly()
        journal.record("READBACK_ACCEPTED" if authority.action == "unit_readback" else "PREFLIGHT_ACCEPTED")
        return {"accepted": False, "observation": result}
    finally:
        try:
            session.cleanup()
        finally:
            session.close()


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("offline", "live"), default="offline")
    args = parser.parse_args(argv)
    require(args.mode == "offline", "Live activation denied; independent source-specific review required")
    print("W2.4C proposal only: no connector, resources, credentials, SQL or execution approval")


if __name__ == "__main__":
    main()
