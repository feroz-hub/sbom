from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from app.db import SessionLocal
from app.models import ComponentLifecycleCache, SBOMComponent, SBOMSource
from app.services.lifecycle import LifecycleEnrichmentService, normalize_component
from app.services.lifecycle.lifecycle_cache_repository import (
    LIFECYCLE_CACHE_IDENTITY_CONSTRAINT,
    lifecycle_cache_identity_key,
    lifecycle_cache_row_from_result,
    upsert_lifecycle_cache_entries,
)
from app.services.lifecycle.provider_base import LifecycleProvider
from app.services.lifecycle.types import (
    EOL,
    HIGH,
    UNKNOWN,
    LifecycleResult,
    NormalizedComponent,
)
from sqlalchemy import func, select


@pytest.fixture()
def db(client):
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


class StaticProvider(LifecycleProvider):
    name = "Static Provider"

    def __init__(self, *, status: str = EOL, source_name: str | None = None) -> None:
        self.status = status
        self.source_name = source_name or self.name

    def lookup(self, component: NormalizedComponent) -> LifecycleResult:
        return LifecycleResult(
            component_name=component.normalized_name,
            component_version=component.normalized_version,
            ecosystem=component.ecosystem,
            purl=component.purl,
            lifecycle_status=self.status,
            source_name=self.source_name,
            confidence=HIGH,
            evidence={"provider": self.source_name},
        )


def _future_iso(days: int = 7) -> str:
    return (datetime.now(UTC).replace(microsecond=0) + timedelta(days=days)).isoformat()


def _identity_count(db, *, name: str, version: str, ecosystem: str, purl: str | None) -> int:
    return (
        db.execute(
            select(func.count())
            .select_from(ComponentLifecycleCache)
            .where(
                ComponentLifecycleCache.normalized_name == name,
                ComponentLifecycleCache.normalized_version == version,
                ComponentLifecycleCache.ecosystem == ecosystem,
                ComponentLifecycleCache.purl == purl,
            )
        ).scalar_one()
        or 0
    )


def test_upsert_inserts_new_cache_row(db):
    normalized = NormalizedComponent(
        component_id=None,
        name="valid-lifecycle-runtimes",
        version="1.0.0",
        normalized_name="valid-lifecycle-runtimes",
        normalized_version="1.0.0",
        ecosystem="generic",
        purl="pkg:generic/valid-lifecycle-runtimes@1.0.0",
    )
    result = LifecycleResult(
        component_name=normalized.normalized_name,
        component_version=normalized.normalized_version,
        ecosystem=normalized.ecosystem,
        purl=normalized.purl,
        lifecycle_status=EOL,
        source_name="Test Provider",
        confidence=HIGH,
        checked_at="2026-06-01T00:00:00+00:00",
    )
    row = lifecycle_cache_row_from_result(normalized, result, cache_ttl_days=7)

    upsert_lifecycle_cache_entries(db, [row])
    db.commit()

    assert _identity_count(
        db,
        name="valid-lifecycle-runtimes",
        version="1.0.0",
        ecosystem="generic",
        purl="pkg:generic/valid-lifecycle-runtimes@1.0.0",
    ) == 1


def test_upsert_twice_does_not_duplicate_identity(db):
    normalized = NormalizedComponent(
        component_id=None,
        name="valid-lifecycle-runtimes",
        version="1.0.0",
        normalized_name="valid-lifecycle-runtimes",
        normalized_version="1.0.0",
        ecosystem="generic",
        purl="pkg:generic/valid-lifecycle-runtimes@1.0.0",
    )
    first = lifecycle_cache_row_from_result(
        normalized,
        LifecycleResult(
            component_name=normalized.normalized_name,
            component_version=normalized.normalized_version,
            ecosystem=normalized.ecosystem,
            purl=normalized.purl,
            lifecycle_status=EOL,
            source_name="First Provider",
            confidence=HIGH,
            checked_at="2026-06-01T00:00:00+00:00",
            evidence={"pass": 1},
        ),
        cache_ttl_days=7,
    )
    second = lifecycle_cache_row_from_result(
        normalized,
        LifecycleResult(
            component_name=normalized.normalized_name,
            component_version=normalized.normalized_version,
            ecosystem=normalized.ecosystem,
            purl=normalized.purl,
            lifecycle_status=EOL,
            source_name="Second Provider",
            confidence=HIGH,
            checked_at="2026-06-02T00:00:00+00:00",
            evidence={"pass": 2},
            recommendation="Upgrade to 2.0.0",
        ),
        cache_ttl_days=7,
    )

    upsert_lifecycle_cache_entries(db, [first, second])
    db.commit()

    cached = db.execute(
        select(ComponentLifecycleCache).where(
            ComponentLifecycleCache.normalized_name == "valid-lifecycle-runtimes",
            ComponentLifecycleCache.normalized_version == "1.0.0",
            ComponentLifecycleCache.ecosystem == "generic",
            ComponentLifecycleCache.purl == "pkg:generic/valid-lifecycle-runtimes@1.0.0",
        )
    ).scalar_one()
    assert cached.source_name == "Second Provider"
    assert cached.checked_at == "2026-06-02T00:00:00+00:00"
    assert cached.recommendation == "Upgrade to 2.0.0"
    assert cached.evidence_json == {"pass": 2}
    assert _identity_count(
        db,
        name="valid-lifecycle-runtimes",
        version="1.0.0",
        ecosystem="generic",
        purl="pkg:generic/valid-lifecycle-runtimes@1.0.0",
    ) == 1


def test_upsert_deduplicates_rows_in_same_batch(db):
    normalized = NormalizedComponent(
        component_id=None,
        name="dup-batch",
        version="1.0.0",
        normalized_name="dup-batch",
        normalized_version="1.0.0",
        ecosystem="generic",
        purl="pkg:generic/dup-batch@1.0.0",
    )
    rows = [
        lifecycle_cache_row_from_result(
            normalized,
            LifecycleResult(
                component_name="dup-batch",
                component_version="1.0.0",
                ecosystem="generic",
                purl="pkg:generic/dup-batch@1.0.0",
                lifecycle_status=EOL,
                source_name="First",
                confidence=HIGH,
                checked_at="2026-06-01T00:00:00+00:00",
            ),
            cache_ttl_days=7,
        ),
        lifecycle_cache_row_from_result(
            normalized,
            LifecycleResult(
                component_name="dup-batch",
                component_version="1.0.0",
                ecosystem="generic",
                purl="pkg:generic/dup-batch@1.0.0",
                lifecycle_status=EOL,
                source_name="Last",
                confidence=HIGH,
                checked_at="2026-06-03T00:00:00+00:00",
            ),
            cache_ttl_days=7,
        ),
    ]

    upsert_lifecycle_cache_entries(db, rows)
    db.commit()

    cached = db.execute(
        select(ComponentLifecycleCache).where(ComponentLifecycleCache.normalized_name == "dup-batch")
    ).scalar_one()
    assert cached.source_name == "Last"
    assert _identity_count(
        db,
        name="dup-batch",
        version="1.0.0",
        ecosystem="generic",
        purl="pkg:generic/dup-batch@1.0.0",
    ) == 1


def test_lifecycle_refresh_twice_does_not_raise(client, db):
    sbom = SBOMSource(sbom_name="refresh-twice", sbom_data="{}", status="validated")
    db.add(sbom)
    db.flush()
    component = SBOMComponent(
        sbom_id=sbom.id,
        name="refresh-twice-package",
        version="1.0.0",
        purl="pkg:generic/refresh-twice-package@1.0.0",
        component_type="library",
    )
    db.add(component)
    db.commit()

    first = client.post(f"/api/sboms/{sbom.id}/lifecycle/refresh?force=true")
    assert first.status_code == 200

    second = client.post(f"/api/sboms/{sbom.id}/lifecycle/refresh?force=true")
    assert second.status_code == 200

    assert _identity_count(
        db,
        name="refresh-twice-package",
        version="1.0.0",
        ecosystem="generic",
        purl="pkg:generic/refresh-twice-package@1.0.0",
    ) == 1


def test_force_refresh_updates_existing_cache_row(db):
    sbom = SBOMSource(sbom_name="force-refresh", sbom_data="{}", status="validated")
    db.add(sbom)
    db.flush()
    component = SBOMComponent(
        sbom_id=sbom.id,
        name="force-refresh-package",
        version="1.0.0",
        purl="pkg:generic/force-refresh-package@1.0.0",
        component_type="library",
    )
    db.add(component)
    db.add(
        ComponentLifecycleCache(
            lookup_key="purl:pkg:generic/force-refresh-package@1.0.0",
            normalized_name="force-refresh-package",
            normalized_version="1.0.0",
            ecosystem="generic",
            purl="pkg:generic/force-refresh-package@1.0.0",
            lifecycle_status=UNKNOWN,
            source_name="Stale Provider",
            confidence=HIGH,
            checked_at="2020-01-01T00:00:00+00:00",
            expires_at=_future_iso(),
            evidence_json={"old": True},
            is_stale=False,
        )
    )
    db.commit()

    service = LifecycleEnrichmentService(providers=[StaticProvider(source_name="Fresh Provider")])
    service.enrich_component(db, component, force_refresh=True)
    db.commit()

    cached = db.execute(
        select(ComponentLifecycleCache).where(
            ComponentLifecycleCache.normalized_name == "force-refresh-package",
            ComponentLifecycleCache.normalized_version == "1.0.0",
            ComponentLifecycleCache.ecosystem == "generic",
            ComponentLifecycleCache.purl == "pkg:generic/force-refresh-package@1.0.0",
        )
    ).scalar_one()
    assert cached.source_name == "Fresh Provider"
    assert cached.lifecycle_status == EOL
    assert cached.checked_at != "2020-01-01T00:00:00+00:00"
    assert cached.evidence_json == {"provider": "Fresh Provider"}
    assert _identity_count(
        db,
        name="force-refresh-package",
        version="1.0.0",
        ecosystem="generic",
        purl="pkg:generic/force-refresh-package@1.0.0",
    ) == 1


def test_duplicate_components_in_sbom_write_one_cache_row(db):
    sbom = SBOMSource(sbom_name="dup-components", sbom_data="{}", status="validated")
    db.add(sbom)
    db.flush()
    first = SBOMComponent(
        sbom_id=sbom.id,
        name="dup-components-package",
        version="1.0.0",
        purl="pkg:generic/dup-components-package@1.0.0",
        component_type="library",
        bom_ref="ref-1",
    )
    second = SBOMComponent(
        sbom_id=sbom.id,
        name="dup-components-package",
        version="1.0.0",
        purl="pkg:generic/dup-components-package@1.0.0",
        component_type="library",
        bom_ref="ref-2",
    )
    db.add_all([first, second])
    db.commit()

    service = LifecycleEnrichmentService(providers=[StaticProvider()])
    service.enrich_sbom(db, sbom.id, force_refresh=True)

    assert _identity_count(
        db,
        name="dup-components-package",
        version="1.0.0",
        ecosystem="generic",
        purl="pkg:generic/dup-components-package@1.0.0",
    ) == 1


def test_read_cache_finds_row_when_cpe_differs(db):
    sbom = SBOMSource(sbom_name="cpe-mismatch", sbom_data="{}", status="validated")
    db.add(sbom)
    db.flush()
    component = SBOMComponent(
        sbom_id=sbom.id,
        name="cpe-mismatch-package",
        version="1.0.0",
        purl="pkg:generic/cpe-mismatch-package@1.0.0",
        cpe="cpe:2.3:a:example:cpe_mismatch_package:1.0.0:*:*:*:*:*:*:*",
        component_type="library",
    )
    db.add(component)
    db.add(
        ComponentLifecycleCache(
            lookup_key="purl:pkg:generic/cpe-mismatch-package@1.0.0",
            normalized_name="cpe-mismatch-package",
            normalized_version="1.0.0",
            ecosystem="generic",
            purl="pkg:generic/cpe-mismatch-package@1.0.0",
            cpe=None,
            lifecycle_status=EOL,
            source_name="Cached Provider",
            confidence=HIGH,
            checked_at="2026-06-01T00:00:00+00:00",
            expires_at=_future_iso(),
            evidence_json={"cached": True},
            is_stale=False,
        )
    )
    db.commit()

    service = LifecycleEnrichmentService(providers=[StaticProvider(source_name="Should Not Run")])
    result = service.enrich_component(db, component, force_refresh=False)

    assert result.source_name == "Cached Provider"
    assert _identity_count(
        db,
        name="cpe-mismatch-package",
        version="1.0.0",
        ecosystem="generic",
        purl="pkg:generic/cpe-mismatch-package@1.0.0",
    ) == 1


def test_postgresql_upsert_path_used_for_postgresql_dialect(db):
    normalized = NormalizedComponent(
        component_id=None,
        name="pg-upsert",
        version="1.0.0",
        normalized_name="pg-upsert",
        normalized_version="1.0.0",
        ecosystem="generic",
        purl="pkg:generic/pg-upsert@1.0.0",
    )
    row = lifecycle_cache_row_from_result(
        normalized,
        LifecycleResult(
            component_name="pg-upsert",
            component_version="1.0.0",
            ecosystem="generic",
            purl="pkg:generic/pg-upsert@1.0.0",
            lifecycle_status=EOL,
            source_name="PG Provider",
            confidence=HIGH,
        ),
        cache_ttl_days=7,
    )
    bind = MagicMock()
    bind.dialect.name = "postgresql"
    db.get_bind = MagicMock(return_value=bind)

    with patch(
        "app.services.lifecycle.lifecycle_cache_repository._upsert_with_on_conflict",
    ) as upsert_mock:
        upsert_lifecycle_cache_entries(db, [row])
        upsert_mock.assert_called_once_with(db, [row], dialect="postgresql")


def test_sqlite_upsert_path_used_for_sqlite_dialect(db):
    normalized = NormalizedComponent(
        component_id=None,
        name="sqlite-upsert",
        version="1.0.0",
        normalized_name="sqlite-upsert",
        normalized_version="1.0.0",
        ecosystem="generic",
        purl="pkg:generic/sqlite-upsert@1.0.0",
    )
    row = lifecycle_cache_row_from_result(
        normalized,
        LifecycleResult(
            component_name="sqlite-upsert",
            component_version="1.0.0",
            ecosystem="generic",
            purl="pkg:generic/sqlite-upsert@1.0.0",
            lifecycle_status=EOL,
            source_name="SQLite Provider",
            confidence=HIGH,
        ),
        cache_ttl_days=7,
    )
    bind = MagicMock()
    bind.dialect.name = "sqlite"
    db.get_bind = MagicMock(return_value=bind)

    with patch(
        "app.services.lifecycle.lifecycle_cache_repository._upsert_with_on_conflict",
    ) as upsert_mock:
        upsert_lifecycle_cache_entries(db, [row])
        upsert_mock.assert_called_once_with(db, [row], dialect="sqlite")


def test_lifecycle_cache_identity_key_matches_constraint_columns():
    key = lifecycle_cache_identity_key("Valid-Name", "1.0.0", "generic", "pkg:generic/x@1.0.0")
    assert key == ("valid-name", "1.0.0", "generic", "pkg:generic/x@1.0.0")
    assert LIFECYCLE_CACHE_IDENTITY_CONSTRAINT == "uq_component_lifecycle_cache_identity"


def test_enrich_component_writes_cache_via_upsert(db, monkeypatch):
    sbom = SBOMSource(sbom_name="upsert-hook", sbom_data="{}", status="validated")
    db.add(sbom)
    db.flush()
    component = SBOMComponent(
        sbom_id=sbom.id,
        name="hook-package",
        version="1.0.0",
        component_type="library",
    )
    db.add(component)
    db.commit()

    calls: list[list[dict[str, Any]]] = []

    def capture_upsert(session, entries):  # noqa: ANN001
        calls.append(entries)

    monkeypatch.setattr(
        "app.services.lifecycle.lifecycle_enrichment_service.upsert_lifecycle_cache_entries",
        capture_upsert,
    )

    LifecycleEnrichmentService(providers=[StaticProvider()]).enrich_component(db, component, force_refresh=True)

    assert len(calls) == 1
    assert calls[0][0]["normalized_name"] == normalize_component(component).normalized_name
