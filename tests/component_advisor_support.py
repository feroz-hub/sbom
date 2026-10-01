"""Shared data builder for Secure Component Advisor tests.

Builds tenant → project → product → SBOM → component → run → finding → VEX
context rows through the ORM, binding the owning tenant so the production
cross-tenant write guard stays active (no Core bypass).
"""

import hashlib

from app.core.context import minimal_background_context, tenant_scope
from app.models import (
    AnalysisFinding,
    AnalysisRun,
    Product,
    Projects,
    SBOMComponent,
    SBOMSource,
    VexInvestigation,
)

NOW = "2026-09-30T00:00:00Z"


def purl_key(purl):
    """The canonical key the advisor derives for a versioned PURL."""
    return hashlib.sha256(f"purl:{purl}".encode()).hexdigest()


class World:
    """Tiny builder for tenant → project → product → SBOM → component → finding."""

    def __init__(self, db):
        self.db = db
        self._ids = iter(range(1, 10_000))

    def _add(self, tenant_id, *rows):
        with tenant_scope(minimal_background_context(tenant_id)):
            self.db.add_all(rows)
            self.db.flush()
        return rows[0] if len(rows) == 1 else rows

    def product(self, tenant_id=1, name=None):
        name = name or f"p{next(self._ids)}"
        project = self._add(tenant_id, Projects(tenant_id=tenant_id, project_name=f"proj-{name}", project_status=1))
        product = self._add(
            tenant_id,
            Product(tenant_id=tenant_id, project_id=project.id, name=name, normalized_name=name, slug=name, created_at=NOW),
        )
        return product

    def sbom(self, product, *, active=True, parent=None, analysed=True, run_status="FINDINGS"):
        sbom = self._add(
            product.tenant_id,
            SBOMSource(
                tenant_id=product.tenant_id, projectid=product.project_id, product_id=product.id,
                sbom_name=f"sbom-{next(self._ids)}", is_active=active,
                parent_id=parent.id if parent else None,
            ),
        )
        sbom.run = self.run(sbom) if analysed else None
        if analysed and run_status != "FINDINGS":
            sbom.run.run_status = run_status
        return sbom

    def run(self, sbom, status="FINDINGS"):
        return self._add(
            sbom.tenant_id,
            AnalysisRun(
                tenant_id=sbom.tenant_id, sbom_id=sbom.id, project_id=sbom.projectid, product_id=sbom.product_id,
                run_status=status, started_on=NOW, completed_on=NOW,
            ),
        )

    def component(self, sbom, name, version, *, ecosystem="npm", purl=True, duplicate_of=None, **extra):
        normalized_purl = f"pkg:{ecosystem}/{name}@{version}" if purl and version else None
        return self._add(
            sbom.tenant_id,
            SBOMComponent(
                tenant_id=sbom.tenant_id, sbom_id=sbom.id, name=name, version=version,
                bom_ref=f"ref-{next(self._ids)}", normalized_name=name, normalized_version=version,
                normalized_ecosystem=ecosystem, normalized_purl=normalized_purl, purl=normalized_purl,
                normalized_package_key=f"{ecosystem}:{name}", is_duplicate=duplicate_of is not None,
                duplicate_of_component_id=duplicate_of.id if duplicate_of else None, **extra,
            ),
        )

    def finding(self, component, vuln_id, severity, *, run=None, aliases=None, score=None):
        sbom = self.db.get(SBOMSource, component.sbom_id)
        run = run or sbom.run
        return self._add(
            component.tenant_id,
            AnalysisFinding(
                tenant_id=component.tenant_id, analysis_run_id=run.id, component_id=component.id,
                vuln_id=vuln_id, severity=severity, aliases=aliases, score=score,
                cpe=f"cpe-{next(self._ids)}",
            ),
        )

    def vex(self, component, vuln_id, effective, reconciliation="MATCHED", *, current=True):
        return self._add(
            component.tenant_id,
            VexInvestigation(
                tenant_id=component.tenant_id, sbom_id=component.sbom_id, component_id=component.id,
                component_key=component.id, canonical_vulnerability_id=vuln_id,
                effective_status=effective, reconciliation_status=reconciliation, is_current=current,
                first_seen_at=NOW, last_seen_at=NOW, created_at=NOW,
            ),
        )
