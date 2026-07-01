"""Phase 1 safety net for the DB schema-management consolidation.

Context
-------
The project currently has TWO schema-management paths (see the discovery
report):

  * PostgreSQL (prod) is built by **Alembic** migrations.
  * SQLite (local dev + the default test suite) is built by
    ``Base.metadata.create_all`` + hand-rolled ``_ensure_*`` DDL in
    ``app/main.py`` at startup — Alembic never runs on SQLite.

Later phases will freeze migration ``001`` (remove its ``import app.models``
/ ``create_all``) and delete the startup DDL so Alembic becomes the single
source of truth. Before touching that production code, these tests establish
a safety net proving:

  1. the Alembic chain can build a fresh SQLite database from scratch;
  2. that Alembic-built schema matches the ``create_all`` schema today
     (drift is surfaced, never silently ignored);
  3. migration ``001`` is *not yet* frozen (xfail ratchet for Phase 2);
  4. ``_verify_schema_is_current`` fails closed on a stale Alembic head.

Safety
------
Every test builds **disposable temporary SQLite databases** (``tmp_path`` /
``tmp_path_factory``). Alembic is invoked in a subprocess whose
``DATABASE_URL`` env var points at the temp file, so the parent process's
engine (and the real dev/prod DB) is never touched. No PostgreSQL, Docker,
Redis, or real ``.env`` secret is required.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

# Register every table on Base.metadata exactly as ``alembic/env.py`` does,
# so comparisons see the full model surface (app models + nvd_mirror models).
import app.models  # noqa: F401
import app.nvd_mirror.db.models  # noqa: F401
import pytest
from app.db import Base
from sqlalchemy import create_engine, inspect, text

ROOT = Path(__file__).resolve().parent.parent

# Tables the platform must always have. A representative, high-value subset —
# not the full list — so the assertion stays readable and stable.
IMPORTANT_TABLES = {
    "projects",
    "sbom_source",
    "sbom_component",
    "sbom_analysis_report",
    "analysis_run",
    "analysis_finding",
    "analysis_schedule",
    "ai_fix_batch",
    "sbom_validation_sessions",
    "vulnerability_remediation_audit",
    "tenants",
    "iam_users",
    "tenant_users",
}

# Representative columns that later refactors must not lose.
IMPORTANT_COLUMNS = {
    "sbom_source": {"tenant_id", "is_active", "status", "parent_id"},
    "analysis_run": {"tenant_id", "run_status", "sbom_id"},
    "analysis_finding": {"tenant_id", "analysis_run_id", "score", "severity"},
    "sbom_validation_sessions": {"validation_status", "detected_format"},
}

# The ONE documented, expected difference between a create_all schema and an
# ``alembic upgrade head`` schema: Alembic tracks its own version table.
EXPECTED_TABLES_ONLY_IN_ALEMBIC = {"alembic_version"}


def _alembic_upgrade_head(db_url: str) -> subprocess.CompletedProcess:
    """Run ``alembic upgrade head`` against ``db_url`` in an isolated subprocess.

    The subprocess env overrides only DATABASE_URL, so the parent process
    engine and the real dev/prod databases are untouched. ``alembic/env.py``
    reads DATABASE_URL and (via ``load_dotenv(override=False)``) will NOT let
    the repo ``.env`` override our explicit temp URL.
    """
    env = os.environ.copy()
    env["DATABASE_URL"] = db_url
    env.pop("TEST_POSTGRES_DATABASE_URL", None)  # never let a PG url leak in
    return subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
    )


@pytest.fixture(scope="module")
def alembic_sqlite_db(tmp_path_factory) -> str:
    """A fresh temp SQLite DB built purely by ``alembic upgrade head``."""
    db_path = tmp_path_factory.mktemp("alembic_db") / "alembic.db"
    result = _alembic_upgrade_head(f"sqlite:///{db_path}")
    assert result.returncode == 0, (
        "alembic upgrade head failed on a fresh SQLite DB:\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    return str(db_path)


@pytest.fixture(scope="module")
def create_all_sqlite_db(tmp_path_factory) -> str:
    """A fresh temp SQLite DB built purely by ``Base.metadata.create_all``.

    Uses a throwaway engine bound to a temp file — NOT the app's engine.
    """
    db_path = tmp_path_factory.mktemp("create_all_db") / "create_all.db"
    engine = create_engine(f"sqlite:///{db_path}")
    try:
        Base.metadata.create_all(bind=engine)
    finally:
        engine.dispose()
    return str(db_path)


def _table_columns(db_path: str) -> dict[str, set[str]]:
    engine = create_engine(f"sqlite:///{db_path}")
    try:
        insp = inspect(engine)
        return {t: {c["name"] for c in insp.get_columns(t)} for t in insp.get_table_names()}
    finally:
        engine.dispose()


def _table_indexes(db_path: str) -> dict[str, set[str]]:
    engine = create_engine(f"sqlite:///{db_path}")
    try:
        insp = inspect(engine)
        return {t: {i["name"] for i in insp.get_indexes(t) if i.get("name")} for t in insp.get_table_names()}
    finally:
        engine.dispose()


# ---------------------------------------------------------------------------
# Test 1 — the Alembic chain can build a fresh SQLite database.
# ---------------------------------------------------------------------------


def test_alembic_builds_fresh_sqlite_schema(alembic_sqlite_db: str) -> None:
    """`alembic upgrade head` on an empty SQLite file yields the full schema."""
    cols = _table_columns(alembic_sqlite_db)
    tables = set(cols)

    # Alembic actually ran (its bookkeeping table is present).
    assert "alembic_version" in tables

    # All important tables exist.
    missing_tables = sorted(IMPORTANT_TABLES - tables)
    assert not missing_tables, f"Alembic-built SQLite is missing tables: {missing_tables}"

    # Every model column is present in the Alembic-built DB (model ⊆ db).
    missing_columns: dict[str, list[str]] = {}
    for table in Base.metadata.sorted_tables:
        if table.name not in cols:
            missing_columns[table.name] = ["<table missing>"]
            continue
        diff = sorted(set(table.columns.keys()) - cols[table.name])
        if diff:
            missing_columns[table.name] = diff
    assert missing_columns == {}, f"Alembic schema missing model columns: {missing_columns}"

    # Spot-check high-value columns explicitly.
    for table, expected in IMPORTANT_COLUMNS.items():
        present = cols.get(table, set())
        assert expected <= present, f"{table} missing columns {sorted(expected - present)}"


# ---------------------------------------------------------------------------
# Test 2 — create_all vs Alembic parity (surface drift, don't hide it).
# ---------------------------------------------------------------------------


def test_create_all_matches_alembic_schema(create_all_sqlite_db: str, alembic_sqlite_db: str) -> None:
    """The two schema paths must agree, except for documented differences.

    Measured baseline (2026-07): identical tables/columns/indexes on SQLite,
    the sole difference being the Alembic-only ``alembic_version`` table. Any
    NEW divergence fails this test loudly rather than being ignored.
    """
    cols_a = _table_columns(create_all_sqlite_db)  # create_all
    cols_b = _table_columns(alembic_sqlite_db)  # alembic

    tables_a, tables_b = set(cols_a), set(cols_b)

    # Documented, expected table difference: only ``alembic_version``.
    only_in_alembic = tables_b - tables_a
    only_in_create_all = tables_a - tables_b
    assert only_in_alembic == EXPECTED_TABLES_ONLY_IN_ALEMBIC, (
        "Unexpected tables present only in the Alembic schema: "
        f"{sorted(only_in_alembic - EXPECTED_TABLES_ONLY_IN_ALEMBIC)}"
    )
    assert only_in_create_all == set(), (
        f"Tables present only in the create_all schema: {sorted(only_in_create_all)}"
    )

    # Column parity across every shared table (exclude Alembic bookkeeping).
    shared = (tables_a & tables_b) - EXPECTED_TABLES_ONLY_IN_ALEMBIC
    column_drift: dict[str, dict[str, list[str]]] = {}
    for table in sorted(shared):
        if cols_a[table] != cols_b[table]:
            column_drift[table] = {
                "only_create_all": sorted(cols_a[table] - cols_b[table]),
                "only_alembic": sorted(cols_b[table] - cols_a[table]),
            }
    assert column_drift == {}, f"create_all vs Alembic COLUMN drift: {column_drift}"

    # Index parity where practical (names). Documents current agreement so a
    # future migration-only index (or a model-only index) is caught.
    idx_a = _table_indexes(create_all_sqlite_db)
    idx_b = _table_indexes(alembic_sqlite_db)
    index_drift: dict[str, dict[str, list[str]]] = {}
    for table in sorted(shared):
        ia, ib = idx_a.get(table, set()), idx_b.get(table, set())
        if ia != ib:
            index_drift[table] = {
                "only_create_all": sorted(ia - ib),
                "only_alembic": sorted(ib - ia),
            }
    assert index_drift == {}, f"create_all vs Alembic INDEX drift: {index_drift}"


# ---------------------------------------------------------------------------
# Test 3 — migration 001 is frozen (Phase 2 complete; ratchet against regression).
# ---------------------------------------------------------------------------


def test_migration_001_is_frozen_and_self_contained() -> None:
    """A committed migration must be an immutable snapshot: no live-model
    import and no create_all/drop_all. Frozen in Phase 2 — this test now
    passes and guards against 001 ever regressing to a metadata-driven form."""
    content = (ROOT / "alembic" / "versions" / "001_initial_schema.py").read_text(encoding="utf-8")
    assert "import app.models" not in content, "001 still imports live models"
    assert "from app.models" not in content, "001 still imports live models"
    assert "create_all" not in content, "001 still calls Base.metadata.create_all"
    assert "drop_all" not in content, "001 downgrade still calls drop_all"


# ---------------------------------------------------------------------------
# Test 4 — _verify_schema_is_current fails closed on a stale Alembic head.
# ---------------------------------------------------------------------------


def _alembic_head_revision() -> str:
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    config = Config(str(ROOT / "alembic.ini"))
    heads = ScriptDirectory.from_config(config).get_heads()
    assert len(heads) == 1, f"expected a single Alembic head, found: {heads}"
    return heads[0]


def _seed_alembic_version(db_path: str, version: str) -> None:
    engine = create_engine(f"sqlite:///{db_path}")
    try:
        with engine.begin() as conn:
            conn.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(128) NOT NULL)"))
            conn.execute(text("INSERT INTO alembic_version (version_num) VALUES (:v)"), {"v": version})
    finally:
        engine.dispose()


def test_verify_schema_is_current_raises_on_stale_head(tmp_path, monkeypatch) -> None:
    """A DB whose alembic_version != script head must be refused at boot."""
    import app.main as main_module

    db_path = tmp_path / "stale.db"
    _seed_alembic_version(str(db_path), "001_initial_schema")  # deliberately behind head

    stale_engine = create_engine(f"sqlite:///{db_path}")
    monkeypatch.setattr(main_module, "engine", stale_engine)
    try:
        with pytest.raises(RuntimeError, match="not at Alembic head"):
            main_module._verify_schema_is_current()
    finally:
        stale_engine.dispose()


def test_verify_schema_is_current_passes_at_head(tmp_path, monkeypatch) -> None:
    """The same guard passes when alembic_version == the script head."""
    import app.main as main_module

    db_path = tmp_path / "current.db"
    _seed_alembic_version(str(db_path), _alembic_head_revision())

    current_engine = create_engine(f"sqlite:///{db_path}")
    monkeypatch.setattr(main_module, "engine", current_engine)
    try:
        main_module._verify_schema_is_current()  # must not raise
    finally:
        current_engine.dispose()


# ---------------------------------------------------------------------------
# Data-backfill migrations (Phase 4) — the backfills that used to run on every
# app startup now live in Alembic and are exercised on disposable DBs.
# ---------------------------------------------------------------------------


def _alembic_cmd(db_url: str, *args: str) -> subprocess.CompletedProcess:
    """Run an arbitrary ``alembic`` subcommand against a disposable DB URL."""
    env = os.environ.copy()
    env["DATABASE_URL"] = db_url
    env.pop("TEST_POSTGRES_DATABASE_URL", None)
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
    )


def test_migration_013_reclassifies_legacy_validated_rows(tmp_path) -> None:
    """Migration 013 owns the legacy status backfill (was a startup helper).

    A pre-validator row (status='validated', validated_at IS NULL) must become
    'pending' when the chain reaches revision 013.
    """
    db = tmp_path / "mig013.db"
    url = f"sqlite:///{db}"
    r = _alembic_cmd(url, "upgrade", "012_sbom_validation_columns")
    assert r.returncode == 0, r.stderr

    eng = create_engine(url)
    try:
        with eng.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO sbom_source "
                    "(id, sbom_name, status, error_count, warning_count, is_active, tenant_id, validated_at) "
                    "VALUES (1, 'legacy-app', 'validated', 0, 0, 1, 1, NULL)"
                )
            )
        r = _alembic_cmd(url, "upgrade", "013_reclassify_unvalidated_sbom_source")
        assert r.returncode == 0, r.stderr
        with eng.connect() as conn:
            status = conn.execute(text("SELECT status FROM sbom_source WHERE id = 1")).scalar_one()
        assert status == "pending"
    finally:
        eng.dispose()


def test_migration_040_backfills_null_sbom_name(tmp_path) -> None:
    """Migration 040 backfills analysis_run.sbom_name from sbom_source, is
    scoped to NULL rows, and is idempotent (re-running head is a no-op)."""
    db = tmp_path / "mig040.db"
    url = f"sqlite:///{db}"
    # Stop one revision short of 040 so we can seed a legacy row first.
    r = _alembic_cmd(url, "upgrade", "039_validation_workspace_large_file")
    assert r.returncode == 0, r.stderr

    eng = create_engine(url)
    try:
        with eng.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO sbom_source "
                    "(id, sbom_name, status, error_count, warning_count, is_active, tenant_id) "
                    "VALUES (1, 'legacy-app', 'validated', 0, 0, 1, 1)"
                )
            )
            # analysis_run with a NULL sbom_name (the legacy shape 040 fixes),
            # plus a second row whose sbom_name is already set (must be untouched).
            base_cols = (
                "run_status, source, started_on, completed_on, duration_ms, total_components, "
                "components_with_cpe, total_findings, critical_count, high_count, medium_count, "
                "low_count, unknown_count, query_error_count, is_active, tenant_id"
            )
            base_vals = "'OK', 'test', '2026-01-01', '2026-01-01', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1"
            conn.execute(
                text(f"INSERT INTO analysis_run (id, sbom_id, sbom_name, {base_cols}) VALUES (1, 1, NULL, {base_vals})")
            )
            conn.execute(
                text(f"INSERT INTO analysis_run (id, sbom_id, sbom_name, {base_cols}) VALUES (2, 1, 'kept', {base_vals})")
            )

        r = _alembic_cmd(url, "upgrade", "head")
        assert r.returncode == 0, r.stderr

        with eng.connect() as conn:
            names = dict(conn.execute(text("SELECT id, sbom_name FROM analysis_run ORDER BY id")).all())
        assert names[1] == "legacy-app", "NULL sbom_name should be backfilled from sbom_source"
        assert names[2] == "kept", "already-set sbom_name must not be overwritten"

        # Idempotent: re-running head touches nothing.
        r = _alembic_cmd(url, "upgrade", "head")
        assert r.returncode == 0, r.stderr
        with eng.connect() as conn:
            names2 = dict(conn.execute(text("SELECT id, sbom_name FROM analysis_run ORDER BY id")).all())
        assert names2 == names
    finally:
        eng.dispose()


def test_migration_040_no_op_on_empty_analysis_run(tmp_path) -> None:
    """A fresh chain to head (empty analysis_run) applies 040 cleanly."""
    db = tmp_path / "mig040_empty.db"
    url = f"sqlite:///{db}"
    r = _alembic_cmd(url, "upgrade", "head")
    assert r.returncode == 0, r.stderr
    cur = _alembic_cmd(url, "current")
    assert "040_backfill_analysis_run_sbom_names" in (cur.stdout + cur.stderr)
