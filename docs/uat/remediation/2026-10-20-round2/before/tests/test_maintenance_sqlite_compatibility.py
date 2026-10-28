"""Keep supported local SQLite startup compatible with maintenance auditing."""

import os
import subprocess
import sys
from pathlib import Path


def test_startup_repair_releases_write_lock_before_audit(tmp_path):
    environment = os.environ.copy()
    environment["DATABASE_URL"] = f"sqlite:///{tmp_path / 'maintenance_test.db'}"
    environment["APP_ENVIRONMENT"] = "test"
    script = """
from datetime import UTC, datetime
from app.core.context import minimal_background_context, tenant_scope
from app.db import Base, SessionLocal, engine
from app.main import _ensure_seed_data
from app.models import SBOMSource, Tenant
from app.settings import get_settings
get_settings().auth_enabled = True
Base.metadata.create_all(engine)
with SessionLocal() as db:
    now = datetime.now(UTC)
    db.add(Tenant(id=1, name='Local', slug='local', status='ACTIVE', created_at=now, updated_at=now))
    db.commit()
with tenant_scope(minimal_background_context(1)), SessionLocal() as db:
    db.add(SBOMSource(tenant_id=1, sbom_name='local repair', status='validated'))
    db.commit()
_ensure_seed_data()
with tenant_scope(minimal_background_context(1)), SessionLocal() as db:
    from sqlalchemy import select
    assert db.scalar(select(SBOMSource.status)) == 'pending'
print('sqlite-maintenance-ok')
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).resolve().parents[1],
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "sqlite-maintenance-ok" in result.stdout
