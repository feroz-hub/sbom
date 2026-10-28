"""Existing tests on a separate new task-owned PostgreSQL database, never the app DB."""

from __future__ import annotations

import fcntl
import os
import signal
import subprocess
import sys

from scripts.greenfield_uuid import ROOT, STATE, settings, url as greenfield_url, verify_resources

DB = "sbom_greenfield_uuid_round4_acceptance2_test_20261020"


def url(user, filename, database=DB):
    # Dedicated fresh remediation-test database; never redirect to the app DB.
    from sqlalchemy.engine import make_url
    if database not in {"postgres", DB} or not DB.endswith("_20261020") or "_test_" not in DB:
        raise RuntimeError("Unexpected remediation regression database")
    return make_url(greenfield_url(user, filename, "postgres")).set(database=database).render_as_string(hide_password=False)


def main():
    # These existing suites truncate the same task-owned database per test.
    # Refuse a second process rather than allowing cross-suite interference.
    lock = open(STATE / "uat-round4-acceptance2.lock", "a")
    os.chmod(STATE / "uat-round4-acceptance2.lock", 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise RuntimeError("Another greenfield regression suite owns the test database") from None
    verify_resources()
    os.environ.update(settings())
    os.chdir(STATE)
    from app.greenfield_schema import application_metadata

    metadata = application_metadata()
    from app.public_identity import install_guards
    from sqlalchemy import create_engine, inspect, text

    control = create_engine(
        url("greenfield_setup", "setup-password", "postgres"), isolation_level="AUTOCOMMIT", hide_parameters=True
    )
    with control.connect() as c:
        if not c.execute(text("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=:db)"), {"db": DB}).scalar_one():
            c.exec_driver_sql("CREATE DATABASE " + DB)
    control.dispose()
    engine = create_engine(url("greenfield_setup", "setup-password", DB), hide_parameters=True)
    with engine.begin() as c:
        if not inspect(c).has_table("alembic_version"):
            metadata.create_all(c)
            install_guards(c)
            c.exec_driver_sql("CREATE TABLE alembic_version(version_num varchar(128) PRIMARY KEY)")
            c.execute(text("INSERT INTO alembic_version VALUES(:revision)"), {"revision": "100_greenfield_uuid_final"})
    engine.dispose()
    env = {k: v for k, v in os.environ.items() if k in ("HOME", "PATH", "TMPDIR", "LANG")}
    env.update(
        PYTHONPATH=str(ROOT),
        PYTHON_DOTENV_DISABLED="1",
        PYTHONDONTWRITEBYTECODE="1",
        TEST_DATABASE_URL=url("greenfield_setup", "setup-password", DB),
        TEST_POSTGRES_DATABASE_URL=url("greenfield_setup", "setup-password", DB),
        DATABASE_URL=url("greenfield_setup", "setup-password", DB),
    )
    if os.getenv('ROUND4_EXACT_SELECTION'):
        env['PYTEST_PLUGINS'] = 'round4_exact_selection'
        env['PYTHONPATH'] += os.pathsep + str(ROOT / 'docs/uat/round4/evidence')
    import json
    redis_config = json.loads((STATE / 'round4-redis/connection.json').read_text())
    env['AI_TEST_REDIS_URL'] = f"redis://127.0.0.1:{redis_config['port']}/0"
    env['LIFECYCLE_LIVE_SMOKE'] = '1'
    env['SBOM_RUN_BACKUP_ACCEPTANCE'] = '1'
    env['SBOM_ACCEPTANCE_PG_CONTAINER'] = 'sbom-greenfield-uuid-dev-postgres-1'
    env['PYTEST_PLUGINS'] = 'round4_results_plugin_attempt2'
    env['PYTHONPATH'] += os.pathsep + str(ROOT / 'docs/uat/round4/evidence')
    files = sys.argv[1:] or [
        "tests/test_native_iam_foundation.py",
        "tests/test_native_iam_phase2.py",
        "tests/test_native_iam_phase3.py",
        "tests/test_native_iam_phase4.py",
        "tests/test_native_iam_phase5.py",
    ]
    command = [sys.executable, "-B", "-m", "pytest", "-q", "--tb=short", "--disable-warnings"] + [
        str(ROOT / f) if f.startswith("tests/") else f for f in files
    ]
    signal.signal(signal.SIGINT, signal.default_int_handler)
    return subprocess.run(command, env=env, cwd=ROOT).returncode


if __name__ == "__main__":
    sys.exit(main())
