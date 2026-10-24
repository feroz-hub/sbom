"""One-connection proposed bridge to reviewed future execution copies only."""

from __future__ import annotations

import connection
import recipe
from kernel import Session, require


class Transport:
    def __init__(
        self,
        *,
        authority,
        options,
        expected_options,
        environment,
        clean_environment,
        resource_gate,
        secret,
        connector,
        meter,
        journal,
        factories,
    ):
        self.authority, self.options, self.expected_options = authority, options, expected_options
        self.environment, self.clean_environment, self.resource_gate = environment, clean_environment, resource_gate
        self.secret, self.connector, self.meter, self.journal = secret, connector, meter, journal
        self.factories = factories
        self.session = self.driver = None
        self.opened = False

    def open(self):
        require(not self.opened, "Second open forbidden")
        self.opened = True
        self.driver = connection.once(
            self.authority,
            approved_options=self.options,
            expected_options=self.expected_options,
            clean_environment=self.clean_environment,
            environment=self.environment,
            resource_gate=self.resource_gate,
            secret=self.secret,
            connector=self.connector,
            meter=self.meter,
            journal=self.journal,
        )
        conn = engine = None
        try:
            conn, engine = recipe.bind(self.driver, **self.factories)
            self.session = Session(conn, self.driver, engine, self.meter, self.journal)
            return conn
        except Exception:
            try:
                self.driver.close()
            finally:
                try:
                    if conn is not None:
                        conn.close()
                finally:
                    if engine is not None:
                        engine.dispose()
            raise

    def close(self):
        if self.session is not None:
            self.session.close()
        elif self.driver is not None:
            self.driver.close()


def control(transport, meter, statement):
    """Drop-in proposed mapping, no literal BEGIN before psycopg implicit BEGIN."""
    session = transport.session
    require(session is not None and session.meter is meter, "Wrong owned transport")
    if statement == "BEGIN READ ONLY":
        session.begin("ro")
        session.initialize(recipe.initializer)
    elif statement == "BEGIN READ WRITE":
        session.begin("rw")
    elif statement == "ROLLBACK":
        if session.driver.owner == "ro" and not meter.cleanup:
            session.finish_readonly()
        else:
            session.end("rollback")
    elif statement == "COMMIT":
        session.end("commit")
    else:
        raise ValueError("Unreviewed transaction control")


def connection_options(authority):
    """Exact future wrapper representation; old approved manifests cannot match."""
    ua = authority.unit_authority
    original = authority.modules["authority"].connection_contract(ua.unit, readback=ua.args[2] == "unit_readback")
    return {
        **original,
        "autocommit": False,
        "application_name": "sbom_w24a_f_readback" if ua.args[2] == "unit_readback" else "sbom_w24a_f_unit",
    }
