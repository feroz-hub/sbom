"""Explicit opt-in live API → disposable PostgreSQL → report smoke.

LIFECYCLE_LIVE_SMOKE=1 .venv/bin/python -m pytest -m integration tests/test_lifecycle_provider_live.py -q
"""

import os
from datetime import UTC, datetime

import pytest
from app.db import SessionLocal
from app.models import SBOMComponent, SBOMSource
from app.services.lifecycle.lifecycle_enrichment_service import LifecycleEnrichmentService
from app.services.lifecycle.provider_config_service import LifecycleProviderConfigService
from sqlalchemy import select

from tests.tenant_fixture_scope import verified_fixture_tenant


@pytest.mark.integration
@pytest.mark.skipif(os.getenv("LIFECYCLE_LIVE_SMOKE") != "1", reason="Live network smoke is explicit opt-in")
def test_live_lifecycle_provider_persistence_and_report(client):
    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        config = LifecycleProviderConfigService()
        for row in config.list_configs(db):
            config.update_config(db, row.provider_key, {"enabled": row.provider_key == "endoflife_date"}, context=None)
        source = SBOMSource(sbom_name="authorized-disposable-live-lifecycle-smoke", sbom_data="{}", status="validated")
        db.add(source)
        db.flush()
        for version in ("3.7.1", "3.12.1"):
            db.add(
                SBOMComponent(
                    sbom_id=source.id,
                    name="Python",
                    version=version,
                    purl=f"pkg:generic/python@{version}",
                    component_type="application",
                )
            )
        db.commit()
        started = datetime.now(UTC).replace(microsecond=0)
        result = LifecycleEnrichmentService().enrich_sbom(db, source.id, force_refresh=True)
        assert not result["provider_errors"], result["provider_errors"]
        rows = list(db.scalars(select(SBOMComponent).where(SBOMComponent.sbom_id == source.id)))
        assert len(rows) == 2
        for row in rows:
            assert row.lifecycle_source == "endoflife.date"
            assert row.lifecycle_confidence == "High"
            assert row.lifecycle_evidence_json.get("cycle")
            assert row.eol_date or row.eos_date or row.eof_date
            assert datetime.fromisoformat(row.lifecycle_checked_at) >= started
        # No assumed EOL dates/statuses: these must come from the live matched cycles.
        report = LifecycleEnrichmentService().lifecycle_report(db, source.id)
        assert {item["lifecycle_status"] for item in report["components"]} == {row.lifecycle_status for row in rows}
        assert LifecycleEnrichmentService().enrich_sbom(db, source.id)["cache_hits"] == 2
