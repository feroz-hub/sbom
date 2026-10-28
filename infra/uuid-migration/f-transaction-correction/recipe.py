"""Explicit SQLAlchemy construction recipe; injected factories, no live wiring.

Avoid Engine.connect()'s automatic initialize/finally-rollback. Construct a
separate public Engine/NullPool/Connection, then initialize explicitly inside
Session's first READ ONLY transaction. No monkeypatch to dialect or migrations.
Native helper/proxy and installed dependency source compatibility need separate
PG16 acceptance; no raw-driver unwrapping or skipped initialization is allowed.
"""

from __future__ import annotations

from kernel import require


def bind(driver, *, dialect_factory, pool_factory, engine_factory, url_factory, connection_factory):
    require(driver.autocommit is False, "Non-autocommit required")
    calls = 0

    def creator():
        nonlocal calls
        require(calls == 0, "Second pool checkout/connection refused")
        calls += 1
        return driver

    engine = None
    try:
        dialect = dialect_factory()  # reviewed psycopg dialect/default native adapters, NOT mock dialect
        require(dialect.name == "postgresql", "Only PostgreSQL")
        setup = dialect.on_connect()
        if setup is not None:
            setup(driver)  # adapters/notice handler only, while IDLE; any SQL is refused
        require(
            driver.raw.info.transaction_status.name == "IDLE"
            if hasattr(driver.raw.info.transaction_status, "name")
            else driver.raw.info.transaction_status == "IDLE",
            "on_connect opened a transaction",
        )
        pool = pool_factory(creator=creator, reset_on_return=None, dialect=dialect)
        engine = engine_factory(pool=pool, dialect=dialect, url=url_factory("postgresql+psycopg://"))
        # Public Connection constructor accepts _allow_revalidate=False: pinned
        # implementation detail must be re-reviewed on dependency changes.
        connection = connection_factory(engine, _allow_revalidate=False)
        require(calls == 1 and connection.connection.driver_connection is driver, "Unexpected physical binding")
        require(not connection.in_transaction(), "Construction caused autobegin")
        return connection, engine
    except Exception:
        try:
            driver.close()
        finally:
            if engine is not None:
                engine.dispose()
        raise


def initializer(connection):
    """Do not run SQLAlchemy's built-in finally/do_rollback wrapper.

    on_connect is called while IDLE, before Session.begin(), by a future reviewed
    provider. Here initialize() itself must run inside the already-owned RO tx.
    No synthetic dialect version/schema is assigned in place of discovery.
    """
    require(connection.in_transaction(), "Owned initialization required")
    connection.dialect.initialize(connection)
