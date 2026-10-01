"""Secure Component Advisor performance benchmark (NFR-SCA-005, prompt §10 T44).

Opt-in: excluded by the default ``-m "not integration and not bench"``. Run::

    pytest -m bench tests/test_component_advisor_bench.py -s

Scale (environment, defaults in brackets):

* ``SCA_BENCH_SBOMS`` [100] — active HEAD SBOMs in the tenant.
* ``SCA_BENCH_COMPONENTS`` [200] — component occurrences per SBOM.
* ``SCA_BENCH_VERSION_POOL`` [5000] — distinct versions occurrences are drawn
  from, so versions recur across SBOMs like real adoption.
* ``SCA_BENCH_ITERATIONS`` [20] — warm requests per endpoint.

The proposed sign-off dataset (phase0-analysis.md §10) is
``SCA_BENCH_SBOMS=500 SCA_BENCH_COMPONENTS=400 SCA_BENCH_VERSION_POOL=25000``.
A second tenant carries noise data that must never be read.

Targets: summary ≤ 2 s p95 warm; drill-down / search ≤ 3 s p95 warm.
Cold (first, uncached) timings are reported, not asserted.
"""

import os
import random
import statistics
import time

import pytest
from sqlalchemy import text

from app.db import SessionLocal
from app.metrics.cache import reset_cache
from app.models import AnalysisFinding, AnalysisRun, Product, Projects, SBOMComponent, SBOMSource, VexInvestigation

pytestmark = pytest.mark.bench

BASE = "/api/component-advisor"
NOW = "2026-09-30T00:00:00Z"
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
VEX_STATES = ("AFFECTED", "UNDER_INVESTIGATION", "NOT_AFFECTED", "FIXED")


def _env(name, default):
    return int(os.environ.get(name, default))


def _load(db, tenant_id, sboms, per_sbom, pool, seed):
    rng = random.Random(seed)
    db.execute(Projects.__table__.insert(), [{"tenant_id": tenant_id, "project_name": f"bench-{tenant_id}-{i}", "project_status": 1, "is_active": True} for i in range(20)])
    project_ids = [r[0] for r in db.execute(text("SELECT id FROM projects WHERE tenant_id = :t ORDER BY id"), {"t": tenant_id})]
    db.execute(
        Product.__table__.insert(),
        [
            {"tenant_id": tenant_id, "project_id": project_ids[i % len(project_ids)], "name": f"app-{tenant_id}-{i}",
             "normalized_name": f"app-{tenant_id}-{i}", "slug": f"app-{tenant_id}-{i}", "created_at": NOW, "is_active": True}
            for i in range(100)
        ],
    )
    products = list(db.execute(text("SELECT id, project_id FROM products WHERE tenant_id = :t ORDER BY id"), {"t": tenant_id}))
    db.execute(
        SBOMSource.__table__.insert(),
        [
            {"tenant_id": tenant_id, "sbom_name": f"sbom-{tenant_id}-{i}", "projectid": products[i % len(products)][1],
             "product_id": products[i % len(products)][0], "is_active": True, "status": "validated",
             "error_count": 0, "warning_count": 0}
            for i in range(sboms)
        ],
    )
    sbom_ids = [r[0] for r in db.execute(text("SELECT id FROM sbom_source WHERE tenant_id = :t ORDER BY id"), {"t": tenant_id})]
    db.execute(
        AnalysisRun.__table__.insert(),
        [{"tenant_id": tenant_id, "sbom_id": s, "run_status": "FINDINGS", "source": "NVD", "started_on": NOW,
          "completed_on": NOW, "duration_ms": 0, "is_active": True} for s in sbom_ids],
    )
    run_of = dict(db.execute(text("SELECT sbom_id, id FROM analysis_run WHERE tenant_id = :t"), {"t": tenant_id}).all())

    components = []
    for s in sbom_ids:
        for idx in rng.sample(range(pool), min(per_sbom, pool)):
            name, version = f"pkg{idx // 5}", f"1.{idx % 5}.0"
            purl = f"pkg:npm/{name}@{version}"
            components.append({
                "tenant_id": tenant_id, "sbom_id": s, "name": name, "version": version, "bom_ref": f"{s}-{idx}",
                "normalized_name": name, "normalized_version": version, "normalized_ecosystem": "npm",
                "normalized_purl": purl, "purl": purl, "normalized_package_key": f"npm:{name}",
                "is_duplicate": False, "lifecycle_is_stale": False, "lifecycle_manual_override": False,
                "lifecycle_status": rng.choice(("Supported", "EOL", "Unknown", None)), "is_active": True,
            })
    for start in range(0, len(components), 5000):
        db.execute(SBOMComponent.__table__.insert(), components[start : start + 5000])
    rows = db.execute(text("SELECT id, sbom_id FROM sbom_component WHERE tenant_id = :t"), {"t": tenant_id}).all()

    findings, contexts = [], []
    for component_id, sbom_id in rows:
        if rng.random() > 0.3:
            continue
        vuln = f"CVE-2026-{rng.randrange(1000, 99999)}"
        findings.append({"tenant_id": tenant_id, "analysis_run_id": run_of[sbom_id], "component_id": component_id,
                         "vuln_id": vuln, "severity": rng.choice(SEVERITIES), "score": rng.uniform(0, 10),
                         "cpe": f"cpe-{component_id}", "is_active": True})
        if rng.random() < 0.6:
            contexts.append({"tenant_id": tenant_id, "sbom_id": sbom_id, "component_id": component_id,
                             "component_key": component_id, "canonical_vulnerability_id": vuln,
                             "effective_status": rng.choice(VEX_STATES), "reconciliation_status": "MATCHED",
                             "unresolved_discriminator": "", "is_current": True, "first_seen_at": NOW,
                             "last_seen_at": NOW, "created_at": NOW, "row_version": 1})
    for start in range(0, len(findings), 5000):
        db.execute(AnalysisFinding.__table__.insert(), findings[start : start + 5000])
    for start in range(0, len(contexts), 5000):
        db.execute(VexInvestigation.__table__.insert(), contexts[start : start + 5000])
    return len(components), len(findings)


def _p95(samples):
    return statistics.quantiles(samples, n=20)[-1] if len(samples) >= 2 else samples[0]


def _time(client, path, params, iterations):
    samples = []
    for _ in range(iterations):
        start = time.perf_counter()
        response = client.get(f"{BASE}{path}", params=params)
        samples.append(time.perf_counter() - start)
        assert response.status_code == 200, response.text
    return samples


def test_T44_component_advisor_benchmark__NFR_SCA_005(client):
    sboms = _env("SCA_BENCH_SBOMS", 100)
    per_sbom = _env("SCA_BENCH_COMPONENTS", 200)
    pool = _env("SCA_BENCH_VERSION_POOL", 5000)
    iterations = _env("SCA_BENCH_ITERATIONS", 20)
    with SessionLocal() as db:
        db.execute(
            text("INSERT INTO tenants (id, name, slug, external_iam_tenant_id, status, created_at, updated_at) "
                 "VALUES (2, 'Noise', 'noise', 'noise', 'ACTIVE', :n, :n) ON CONFLICT (id) DO NOTHING"),
            {"n": NOW},
        )
        start = time.perf_counter()
        occurrences, findings = _load(db, 1, sboms, per_sbom, pool, seed=1)
        _load(db, 2, max(1, sboms // 5), per_sbom, pool, seed=2)
        db.commit()
        load_seconds = time.perf_counter() - start
        # Bulk loads leave the planner without statistics until autovacuum
        # runs; production tables always have them, so measure with them.
        for table in ("sbom_source", "sbom_component", "analysis_run", "analysis_finding",
                      "vex_investigation", "products", "projects"):
            db.execute(text(f"ANALYZE {table}"))
        db.commit()

    reset_cache()
    start = time.perf_counter()
    cold = client.get(f"{BASE}/summary")
    cold_seconds = time.perf_counter() - start
    assert cold.status_code == 200
    unique = next(card for card in cold.json()["kpis"] if card["key"] == "unique_component_versions")["value"]

    results = {
        "summary": _time(client, "/summary", {}, iterations),
        "summary_filtered": _time(client, "/summary", {"risk": "CRITICAL,HIGH"}, iterations),
        "components": _time(client, "/components", {"limit": 50}, iterations),
        "components_filtered": _time(client, "/components", {"lifecycle": "EOL", "sort_by": "products"}, iterations),
        "search": _time(client, "/search", {"q": "pkg1"}, iterations),
    }
    report = {name: round(_p95(samples), 3) for name, samples in results.items()}
    print(
        f"\nSCA benchmark: sboms={sboms} occurrences={occurrences} unique_versions={unique} findings={findings} "
        f"load={load_seconds:.1f}s cold_summary={cold_seconds:.2f}s warm_p95={report}"
    )
    assert report["summary"] <= 2.0 and report["summary_filtered"] <= 2.0
    assert report["components"] <= 3.0 and report["components_filtered"] <= 3.0 and report["search"] <= 3.0
