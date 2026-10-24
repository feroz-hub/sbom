"""Foreign VEX fixtures created with their true owner; no ownership transfer."""

from app.models import AnalysisFinding, AnalysisRun, SBOMComponent, SBOMSource, VexInvestigation
from app.services.vex.reconciliation import recompute_for_sbom
from sqlalchemy import select

from tests.tenant_fixture_scope import declare_fixture_tenant, verified_fixture_tenant


def foreign_vex_fixture(db, tenant_id=2, vuln_id="CVE-2026-5001"):
    declare_fixture_tenant(db, tenant_id)
    db.commit()
    with verified_fixture_tenant(db, tenant_id):
        sbom = SBOMSource(tenant_id=tenant_id, sbom_name="foreign-vex", sbom_data="{}", is_active=True)
        db.add(sbom)
        db.flush()
        component = SBOMComponent(tenant_id=tenant_id, sbom_id=sbom.id, name="openssl", version="1.1.1",
                                  purl="pkg:generic/openssl@1.1.1")
        db.add(component)
        db.flush()
        run = AnalysisRun(tenant_id=tenant_id, sbom_id=sbom.id, run_status="OK",
                          started_on="2026-10-08T00:00:00Z", completed_on="2026-10-08T00:00:00Z")
        db.add(run)
        db.flush()
        db.add(AnalysisFinding(tenant_id=tenant_id, analysis_run_id=run.id, component_id=component.id,
                               vuln_id=vuln_id, source="NVD", severity="HIGH"))
        db.commit()
        recompute_for_sbom(db, tenant_id=tenant_id, sbom_id=sbom.id)
        db.commit()
        context = db.scalar(select(VexInvestigation).where(VexInvestigation.sbom_id == sbom.id,
                            VexInvestigation.canonical_vulnerability_id == vuln_id))
        assert context is not None
        return {"sbom_id": sbom.id, "component_id": component.id, "context_id": context.id,
                "row_version": context.row_version}


def foreign_vex_snapshot(db, tenant_id, context_id):
    with verified_fixture_tenant(db, tenant_id):
        table = VexInvestigation.__table__
        return tuple(db.execute(select(table).where(table.c.id == context_id)).one())
