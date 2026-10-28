"""Single-attempt DI connection proposal; no actual connector/secret provider."""

from __future__ import annotations

from kernel import Driver, require, status


def options(authority, previous_options):
    """Retain every reviewed option except the explicitly proposed autocommit.

    previous_options is the pinned W2.4A function, not caller-supplied kwargs.
    Future source-specific authority must independently approve this new exact
    representation and pin this function. Old manifests do not approve it.
    """
    old = previous_options(authority)
    return {**old, "autocommit": False}


def once(
    authority,
    *,
    approved_options,
    expected_options,
    clean_environment,
    environment,
    resource_gate,
    secret,
    connector,
    meter,
    journal,
):
    """Private future adapter only; no provider is reachable from CLI.

    Native psycopg attributes are set while IDLE, never by SQL or AUTOCOMMIT.
    Dedicated mutable secret erased on every outcome; Python/driver copies may
    remain, as in the original reviewed credential-memory limitation.
    """
    raw = None
    try:
        require(
            approved_options == expected_options and expected_options["autocommit"] is False,
            "Exact new source-specific connection authority required",
        )
        require(
            set(expected_options)
            == {
                "host",
                "hostaddr",
                "port",
                "dbname",
                "user",
                "passfile",
                "sslmode",
                "gssencmode",
                "connect_timeout",
                "autocommit",
                "application_name",
                "options",
            },
            "Unreviewed connection keyword",
        )
        require(
            expected_options["application_name"] in {"sbom_w24a_f_unit", "sbom_w24a_f_readback"}
            and isinstance(expected_options["options"], str)
            and bool(expected_options["options"]),
            "Exact reviewed application/session options required",
        )
        require(
            expected_options["host"] == expected_options["hostaddr"] == "127.0.0.1"
            and expected_options["port"] == 56043
            and expected_options["dbname"] == "uuid_w2_f_fresh"
            and expected_options["user"] == "uuid_w2_f_bootstrap"
            and expected_options["passfile"] == "/dev/null"
            and expected_options["sslmode"] == expected_options["gssencmode"] == "disable"
            and expected_options["connect_timeout"] == 5
            and "service" not in expected_options,
            "Only fixed F connection options",
        )
        require(type(secret) is bytearray and len(secret) > 0, "Memory-only dedicated credential required")
        clean_environment(environment)
        resource_gate(authority)  # original live-correlated resource/secret/source/security gates
        authority.recheck()  # exact raw original manifest, action, expiry, dependencies, sources
        meter.charge("attempts")
        journal.record("CONNECT_REQUESTED")
        raw = connector(**expected_options, password=secret.decode())
        require(status(raw) == "IDLE" and raw.autocommit is False, "Unexpected connection state")
        raw.isolation_level = 2  # psycopg IsolationLevel.READ_COMMITTED, not SQLAlchemy AUTOCOMMIT
        raw.read_only = True
        raw.prepare_threshold = None  # bound driver executions; no automatic PREPARE/cache-maintenance commands
        return Driver(raw, meter, journal)
    except Exception:
        if raw is not None:
            raw.close()
        raise
    finally:
        if isinstance(secret, bytearray):
            secret[:] = b"\x00" * len(secret)
