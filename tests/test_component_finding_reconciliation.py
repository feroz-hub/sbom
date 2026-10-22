"""Synthetic Run-15-style regressions. No provider or production DB access."""

from __future__ import annotations

import asyncio
import copy
import itertools
import json

import pytest
from app.normalization.component_deduplicator import ComponentDeduplicator
from app.normalization.purl_normalizer import normalize_purl
from app.sources.component_observation import applicable_osv_record
from app.sources.cvss_assessment import assessment, numeric_score, osv_assessment
from app.sources.reconciliation import reconcile

from tests.public_id_fixture import run_uuid

LOG4J = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"


def component(cid=5, **overrides):
    return {
        "component_id": cid,
        "tenant_id": 1,
        "sbom_id": 1,
        "bom_ref": f"ref-{cid}",
        "name": "log4j-core",
        "version": "2.14.1",
        "purl": LOG4J,
        "ecosystem": "Maven",
        **overrides,
    }


def advisory(**overrides):
    return {
        "id": "GHSA-jfh8-c2jp-5v3q",
        "aliases": ["CVE-2021-44228"],
        "severity": [{"type": "CVSS_V3", "score": VECTOR}],
        "affected": [
            {"package": {"name": "unrelated", "ecosystem": "Maven"}, "versions": ["1.0"]},
            {
                "package": {"name": "org.apache.logging.log4j:log4j-core", "ecosystem": "Maven"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "2.15.0"}]}],
            },
        ],
        **overrides,
    }


def observation(provider="NVD", **overrides):
    return {
        "component_id": 5,
        "sbom_id": 1,
        "tenant_id": 1,
        "component_name": "log4j-core",
        "component_version": "2.14.1",
        "vuln_id": "CVE-2021-44228",
        "sources": [provider],
        "aliases": [],
        "severity": "CRITICAL",
        "score": 10.0 if provider == "NVD" else None,
        "vector": VECTOR if provider == "NVD" else None,
        "cvss_version": "3.1" if provider == "NVD" else None,
        "applicability_status": "affected",
        **overrides,
    }


@pytest.mark.parametrize(
    "value,expected",
    [(0, 0.0), (10, 10.0), (-0.1, None), (10.1, None), ("NaN", None), (float("inf"), None), (True, None), ("9.8", 9.8)],
)
def test_numeric_cvss_boundaries(value, expected):
    assert numeric_score(value) == expected


@pytest.mark.parametrize("version", ["3.0", "3.1"])
def test_full_v3_vector_and_optional_metrics(version):
    vector = VECTOR.replace("3.1", version) + "/E:U/RL:O/RC:C"
    result = assessment(None, vector, version)
    assert result["score"] == 10.0
    assert result["vector"] == vector
    assert result["version"] == version
    assert result["assessment_type"] == "base"


def test_v4_vector_and_coherent_numeric_validation():
    vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
    result = assessment(None, vector, "4.0")
    assert result["score"] == 10.0
    assert assessment(3.0, vector, "4.0") is None


@pytest.mark.parametrize(
    "vector,version",
    [
        ("AV:N/AC:L", None),
        ("CVSS:3.1/AV:X", "3.1"),
        (VECTOR, "4.0"),
        ("CVSS:5.0/AV:N", "5.0"),
        (VECTOR + "/AV:L", "3.1"),
    ],
)
def test_malformed_or_mismatched_vectors_are_unscored(vector, version):
    assert assessment(10, vector, version) is None


def test_osv_never_pairs_numeric_from_one_rating_with_another_vector():
    result = osv_assessment({"severity": [{"type": "CVSS_V3", "score": "5.9"}, {"type": "CVSS_V3", "score": VECTOR}]})
    assert result["score"] == 10
    assert result["vector"] == VECTOR
    assert osv_assessment({"severity": [{"type": "CVSS_V4", "score": VECTOR}]}) is None


def test_provider_order_independence_and_duplicate_replay():
    rows = [
        observation(),
        observation("OSV", component_name="org.apache.logging.log4j:log4j-core"),
        observation("GITHUB", vuln_id="GHSA-jfh8-c2jp-5v3q", aliases=["CVE-2021-44228"]),
    ]
    expected = reconcile(rows)
    for ordering in itertools.permutations(rows):
        assert reconcile(list(ordering)) == expected
    assert reconcile([*rows, copy.deepcopy(rows[0])]) == expected
    assert expected[0]["score"] == 10
    assert expected[0]["cvss_source"] == "NVD"
    assert len(expected[0]["source_observations"]) == 3
    assert expected[0]["sources"] == ["GITHUB", "NVD", "OSV"]


def test_severity_conflict_follows_selected_assessment_not_worst_label():
    result = reconcile(
        [
            observation(vuln_id="CVE-2021-45105", score=5.9, vector=None, severity="MEDIUM"),
            observation("OSV", vuln_id="CVE-2021-45105", severity="HIGH"),
        ]
    )[0]
    assert (result["score"], result["severity"], result["cvss_source"]) == (5.9, "MEDIUM", "NVD")
    assert result["rating_disagreement"]
    assert result["source_observations"][1]["severity"] in {"HIGH", "MEDIUM"}


def test_different_occurrences_runs_sboms_and_tenants_remain_separate():
    rows = [
        observation(),
        observation(component_id=6),
        observation(sbom_id=2),
        observation(tenant_id=2),
        observation(analysis_run_id=99),
    ]
    assert len(reconcile(rows)) == 5


def test_multicve_and_conflicting_alias_bridges_do_not_merge_cves():
    rows = [
        observation(vuln_id="CVE-2021-44228"),
        observation(vuln_id="CVE-2021-45046"),
        observation("OSV", vuln_id="GHSA-aaaa-bbbb-cccc", aliases=["CVE-2021-44228", "CVE-2021-45046"]),
    ]
    assert len(reconcile(rows)) == 3
    conflicting = [
        observation("OSV", vuln_id="GHSA-aaaa-bbbb-cccc", aliases=["CVE-2021-44228"]),
        observation("OSV", vuln_id="GHSA-aaaa-bbbb-cccc", aliases=["CVE-2021-45046"]),
    ]
    assert reconcile(conflicting)[0]["vuln_id"] == "GHSA-AAAA-BBBB-CCCC"


def test_unresolved_cpe_or_name_observations_cannot_merge_providers():
    rows = [
        observation(component_id=None, cpe="cpe:2.3:a:a:a:1:*:*:*:*:*:*:*"),
        observation("OSV", component_id=None, cpe="cpe:2.3:a:a:a:1:*:*:*:*:*:*:*"),
    ]
    assert len(reconcile(rows)) == 2
    assert all(r["resolution_status"] == "unresolved" for r in reconcile(rows))


@pytest.mark.parametrize(
    "purl", ["pkg:maven/Org.Example/Artifact@v1.0+Build?classifier=sources#src", "pkg:golang/GitHub.com/Org/Lib@v1.0.0"]
)
def test_case_build_qualifier_subpath_identity_preserved(purl):
    from packageurl import PackageURL

    normalized = normalize_purl(purl).normalized_purl
    assert PackageURL.from_string(normalized) == PackageURL.from_string(purl)


def test_occurrence_preservation_determinism_and_dependency_evidence():
    comps = [
        {"name": "Apache Log4j Core", "version": "2.14.1", "purl": LOG4J, "bom_ref": "b"},
        {"name": "log4j-core", "version": "2.14.1", "purl": LOG4J, "bom_ref": "a"},
    ]
    deps = [{"ref": "app", "dependsOn": ["a", "b"]}]
    canonical, duplicates, _, report, _ = ComponentDeduplicator.deduplicate(comps, deps)
    reversed_canonical, _, *_ = ComponentDeduplicator.deduplicate(list(reversed(comps)), deps)
    assert len(canonical) == len(duplicates) == 1
    assert canonical[0]["bom_ref"] == reversed_canonical[0]["bom_ref"] == "a"
    assert report["original_dependencies"] == deps
    assert {c["original_name"] for c in [*canonical, *duplicates]} == {c["name"] for c in comps}


@pytest.mark.parametrize(
    "overrides",
    [
        {"purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.15.0", "version": "2.15.0"},
        {"hashes": "SHA-256:" + "b" * 64},
        {"scope": "excluded"},
        {"version": "2.15.0"},
        {"purl": LOG4J + "?classifier=sources"},
    ],
)
def test_different_versions_hashes_contexts_and_qualifiers_do_not_group(overrides):
    a = {**component(), "hashes": "SHA-256:" + "a" * 64}
    b = {**component(6), **overrides}
    canonical, duplicates, *_ = ComponentDeduplicator.deduplicate([a, b])
    assert len(canonical) == 2
    assert not duplicates


def test_cpe_only_and_name_only_are_unresolved_and_duplicate_refs_rejected():
    for comps in (
        [
            {"name": "a", "version": "1", "cpe": "cpe:2.3:a:v:p:1:*:*:*:*:*:*:*"},
            {"name": "b", "version": "1", "cpe": "cpe:2.3:a:v:p:1:*:*:*:*:*:*:*"},
        ],
        [{"name": "a", "version": "1", "ecosystem": "npm"}] * 2,
    ):
        canonical, duplicates, *_ = ComponentDeduplicator.deduplicate(comps)
        assert len(canonical) == 2 and not duplicates
        assert all(c["canonical_identity_confidence"] == "Low" for c in canonical)
    with pytest.raises(ValueError, match="Duplicate document"):
        ComponentDeduplicator.deduplicate([component(), component()])


def test_osv_filters_other_packages_and_fixed_versions():
    result = applicable_osv_record(advisory(), component())
    assert len(result["affected"]) == 1
    assert applicable_osv_record(advisory(), component(version="2.17.0")) is None
    assert applicable_osv_record(advisory(withdrawn="2026-01-01"), component()) is None


@pytest.mark.parametrize("cache_hit", [False, True])
def test_osv_query_mapping_hydration_and_cache_replay(monkeypatch, cache_hit):
    import app.analysis as analysis
    from app.sources.cache_seam import component_cache_key

    comps = [
        component(),
        component(6),
        component(7, name="commons-text", version="1.9", purl="pkg:maven/org.apache.commons/commons-text@1.9"),
        component(8, version="2.17.0", purl=LOG4J.replace("2.14.1", "2.17.0")),
    ]
    payload = advisory()

    async def partition(source, keyed, settings):
        return (
            ({component_cache_key(c): {"source_path": "querybatch", "vulns": [payload]} for c in comps}, [])
            if cache_hit
            else ({}, comps)
        )

    async def post(url, json_body, **kwargs):
        assert url.endswith("/querybatch")
        return {"results": [{"vulns": [{"id": payload["id"]}]} for _ in json_body["queries"]]}

    async def get(url, **kwargs):
        return payload

    monkeypatch.setattr(analysis, "_partition_by_cache", partition)
    monkeypatch.setattr(analysis, "_write_cache_entries", lambda *a, **k: None)
    monkeypatch.setattr(analysis, "_async_post", post)
    monkeypatch.setattr(analysis, "_async_get", get)
    rows, errors, _ = asyncio.run(analysis.osv_query_by_components(comps, analysis.get_analysis_settings_multi()))
    assert not errors
    assert {r["component_id"] for r in rows} == {5, 6}
    assert all(r["component_name"] == "log4j-core" and r["component_version"] == "2.14.1" for r in rows)
    assert all(r["score"] == 10 and r["vector"] == VECTOR for r in rows)
    assert all(r["fixed_versions"] == ["2.15.0"] for r in rows)


def test_osv_partial_responses_do_not_cache_failures_as_clean(monkeypatch):
    import app.analysis as analysis

    writes = []

    async def partition(source, keyed, settings):
        return {}, [c for _, c in keyed]

    async def post(url, json_body, **kwargs):
        if url.endswith("querybatch"):
            return {"results": [{"vulns": [{"id": advisory()["id"]}]}]}
        raise RuntimeError("synthetic fallback unavailable")

    async def get(url, **kwargs):
        return advisory()

    monkeypatch.setattr(analysis, "_partition_by_cache", partition)
    monkeypatch.setattr(analysis, "_write_cache_entries", lambda source, entries, **kw: writes.extend(entries))
    monkeypatch.setattr(analysis, "_async_post", post)
    monkeypatch.setattr(analysis, "_async_get", get)
    comps = [component(), component(8, version="2.17.0", purl=LOG4J.replace("2.14.1", "2.17.0"))]
    rows, errors, _ = asyncio.run(analysis.osv_query_by_components(comps, analysis.get_analysis_settings_multi()))
    assert len(rows) == 1 and len(errors) == 2
    assert len(writes) == 1 and "2.14.1" in writes[0][0]


def test_osv_querybatch_pagination_keeps_original_indices(monkeypatch):
    import app.analysis as analysis

    calls = []

    async def partition(source, keyed, settings):
        return {}, [c for _, c in keyed]

    async def post(url, json_body, **kwargs):
        calls.append(json_body)
        if len(calls) == 1:
            return {"results": [{"vulns": [], "next_page_token": "more"}, {"vulns": []}]}
        assert len(json_body["queries"]) == 1 and json_body["queries"][0]["page_token"] == "more"
        return {"results": [{"vulns": [{"id": advisory()["id"]}]}]}

    async def get(url, **kwargs):
        return advisory()

    monkeypatch.setattr(analysis, "_partition_by_cache", partition)
    monkeypatch.setattr(analysis, "_write_cache_entries", lambda *a, **kw: None)
    monkeypatch.setattr(analysis, "_async_post", post)
    monkeypatch.setattr(analysis, "_async_get", get)
    rows, errors, _ = asyncio.run(
        analysis.osv_query_by_components([component(), component(6)], analysis.get_analysis_settings_multi())
    )
    # Same query identity has the same intelligence and fans out to both occurrences.
    assert {r["component_id"] for r in rows} == {5, 6}
    assert not errors


@pytest.fixture()
def reconciliation_db(client):
    from app.db import SessionLocal

    from tests.tenant_fixture_scope import verified_fixture_tenant

    with SessionLocal() as db, verified_fixture_tenant(db, 1):
        yield db
        db.rollback()


def seed_sbom(db, name="reconciliation-fixture"):
    from app.models import SBOMSource

    sbom = SBOMSource(
        sbom_name=name, sbom_data=json.dumps({"bomFormat": "CycloneDX", "components": []}), status="validated"
    )
    db.add(sbom)
    db.flush()
    return sbom


def test_persistence_api_evidence_metrics_vex_and_pagination(client, reconciliation_db):
    from app.models import AnalysisFinding, EpssScore, SBOMComponent
    from app.services.analysis_service import persist_analysis_run
    from app.services.lifecycle.vex_provider import apply_vex_override
    from app.services.sbom_service import _upsert_components

    db = reconciliation_db
    sbom = seed_sbom(db)
    inputs = [{k: v for k, v in component().items() if k not in {"component_id", "tenant_id", "sbom_id"}}]
    maps = _upsert_components(db, sbom, inputs)
    stored = next(iter(maps["ids"].values()))
    apply_vex_override(
        db,
        stored.id,
        "CVE-2021-44228",
        {"status": "not_affected", "reason": "isolated fixture", "justification": "code_not_reachable"},
        changed_by="tester",
    )
    db.merge(EpssScore(cve_id="CVE-2021-44228", epss=0.2, percentile=0.9, refreshed_at="2026-10-15T00:00:00Z"))
    db.flush()
    rows = [
        observation(component_id=stored.id, sbom_id=sbom.id),
        observation(
            "OSV",
            component_id=stored.id,
            sbom_id=sbom.id,
            component_name="org.apache.logging.log4j:log4j-core",
            component_version=None,
        ),
        observation("OSV", component_id=stored.id, sbom_id=sbom.id, vuln_id="CVE-2021-45105", severity="HIGH"),
    ]
    run = persist_analysis_run(
        db,
        sbom,
        {"total_findings": 3, "findings": rows, "analysis_metadata": {"raw_observation_count": 3}},
        [{**inputs[0], "component_id": stored.id}],
        "FINDINGS",
        "NVD,OSV",
        "2026-10-15T00:00:00Z",
        "2026-10-15T00:00:01Z",
        1000,
    )
    db.commit()
    persisted = db.query(AnalysisFinding).filter_by(analysis_run_id=run.id).all()
    assert len(persisted) == 2
    assert db.query(SBOMComponent).filter_by(sbom_id=sbom.id).count() == 1
    response = client.get(f"/api/runs/{run_uuid(run.id)}/findings-enriched?page_size=1")
    assert response.status_code == 200, response.text
    assert response.headers["X-Total-Count"] == "2"
    all_rows = client.get(f"/api/runs/{run_uuid(run.id)}/findings-enriched").json()
    finding = next(r for r in all_rows if r["vuln_id"] == "CVE-2021-44228")
    assert finding["component_id"] == str(stored.public_id)
    assert finding["component_name"] == "log4j-core" and finding["component_version"] == "2.14.1"
    assert finding["score"] == 10 and finding["cvss_source"] == "NVD"
    assert len(finding["source_observations"]) == 2
    assert finding["vex_status"] == "not_affected"
    assert finding["epss"] == 0.2 and finding["epss_percentile"] == 0.9
    assert finding["risk_score"] == 10 * (1 + 5 * 0.2) * (2 if finding["in_kev"] else 1)
    unscored = next(r for r in all_rows if r["vuln_id"] == "CVE-2021-45105")
    assert unscored["score"] is None and unscored["risk_input_estimated"]
    metrics = client.get(f"/api/runs/{run_uuid(run.id)}").json()["metrics"]
    assert (metrics["raw_observation_count"], metrics["total_findings"], metrics["unique_vulnerabilities"]) == (3, 2, 2)
    assert metrics["cvss_coverage"] == 0.5 and metrics["cvss_unknown_findings"] == 1
    filtered = client.get(f"/api/runs/{run_uuid(run.id)}/findings-enriched?severity=CRITICAL")
    assert len(filtered.json()) == 1 and filtered.headers["X-Unfiltered-Total-Count"] == "2"


def test_upsert_preserves_occurrences_ids_and_ambiguous_ownership(reconciliation_db):
    from app.models import SBOMComponent
    from app.services.sbom_service import _upsert_components, resolve_component_id

    db = reconciliation_db
    sbom, foreign_sbom = seed_sbom(db), seed_sbom(db, "other-sbom")
    source = [
        {"name": "log4j-core", "version": "2.14.1", "purl": LOG4J, "bom_ref": "a"},
        {"name": "Apache Log4j Core", "version": "2.14.1", "purl": LOG4J, "bom_ref": "b"},
    ]
    first = _upsert_components(db, sbom, source)
    ids = {r.bom_ref: r.id for r in first["ids"].values()}
    second = _upsert_components(db, sbom, list(reversed(source)))
    assert {r.bom_ref: r.id for r in second["ids"].values()} == ids
    assert db.query(SBOMComponent).filter_by(sbom_id=sbom.id).count() == 2
    assert resolve_component_id({"purl": LOG4J}, second) is None
    assert resolve_component_id({"component_id": ids["b"], "sbom_id": sbom.id}, second) == ids["b"]
    assert resolve_component_id({"component_id": ids["b"], "sbom_id": foreign_sbom.id}, second) is None
    foreign = _upsert_components(db, foreign_sbom, [source[0]])
    foreign_id = next(iter(foreign["ids"]))
    assert resolve_component_id({"component_id": foreign_id}, second) is None
    assert resolve_component_id({"component_id": ids["a"], "tenant_id": 999}, second) is None
    assert resolve_component_id({"component_id": ids["a"], "purl": "pkg:npm/other@1"}, second) is None


def test_reference_less_upsert_is_idempotent(reconciliation_db):
    from app.services.sbom_service import _upsert_components

    db = reconciliation_db
    sbom = seed_sbom(db)
    source = [{"name": "log4j-core", "version": "2.14.1", "purl": LOG4J}]
    assert set(_upsert_components(db, sbom, source)["ids"]) == set(_upsert_components(db, sbom, source)["ids"])


def test_analysis_loads_only_selected_sbom_and_preserves_original_ids(monkeypatch, reconciliation_db):
    import app.services.analysis_orchestrator as module
    from app.services.sbom_service import _upsert_components

    db = reconciliation_db
    a, b = seed_sbom(db, "a"), seed_sbom(db, "b")
    source = [
        {"name": "log4j-core", "version": "2.14.1", "purl": LOG4J, "bom_ref": "a"},
        {"name": "Apache Log4j Core", "version": "2.14.1", "purl": LOG4J, "bom_ref": "b"},
    ]
    maps = _upsert_components(db, a, source)
    _upsert_components(db, b, [source[0]])
    monkeypatch.setattr(module, "_augment_components_with_cpe", lambda components: (components, 0))
    loaded = module.AnalysisOrchestrator(db).load_components(a, run_id=None)
    assert {c["component_id"] for c in loaded} == set(maps["ids"])
    assert all(c["sbom_id"] == a.id and c["tenant_id"] == a.tenant_id for c in loaded)
    assert len(loaded) == 2


def test_reconciliation_is_idempotent_and_does_not_invent_numeric_scores():
    rows = [observation(), observation("OSV")]
    assert reconcile(reconcile(rows)) == reconcile(rows)
    unscored = reconcile([observation("OSV", severity="HIGH")])[0]
    assert unscored["score"] is None and unscored["selected_cvss"] is None


def test_disjoint_osv_ranges_preserve_earlier_affected_interval():
    raw = advisory(
        affected=[
            {
                "package": {"name": "org.apache.logging.log4j:log4j-core", "ecosystem": "Maven"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "2.15.0"}, {"introduced": "3.0"}, {"fixed": "3.1"}],
                    }
                ],
            }
        ]
    )
    assert applicable_osv_record(raw, component()) is not None


def test_spdx_document_occurrences_and_relationships_are_preserved():
    from app.parsing.spdx import parse_spdx_dict

    doc = {
        "spdxVersion": "SPDX-2.3",
        "documentNamespace": "https://example.invalid/document-a",
        "packages": [
            {
                "SPDXID": ref,
                "name": name,
                "versionInfo": "2.14.1",
                "externalRefs": [{"referenceType": "purl", "referenceLocator": LOG4J}],
            }
            for ref, name in [("SPDXRef-a", "log4j-core"), ("SPDXRef-b", "Apache Log4j Core")]
        ],
        "relationships": [
            {"spdxElementId": "SPDXRef-app", "relatedSpdxElement": "SPDXRef-a", "relationshipType": "DEPENDS_ON"},
            {"spdxElementId": "SPDXRef-app", "relatedSpdxElement": "SPDXRef-b", "relationshipType": "DEPENDS_ON"},
        ],
    }
    canonical, duplicates, _, report, _ = ComponentDeduplicator.deduplicate(parse_spdx_dict(doc), doc["relationships"])
    assert {c["bom_ref"] for c in [*canonical, *duplicates]} == {"SPDXRef-a", "SPDXRef-b"}
    assert report["original_dependencies"] == doc["relationships"]
    assert len(canonical) == 1 and len(duplicates) == 1


def test_github_namespace_queries_and_per_occurrence_alias_mapping(monkeypatch):
    from dataclasses import replace

    import app.analysis as analysis

    calls = []

    async def post(url, json_body, **kwargs):
        calls.append(json_body["variables"])
        assert json_body["variables"]["name"] == "org.apache.logging.log4j:log4j-core"
        return {
            "data": {
                "securityVulnerabilities": {
                    "pageInfo": {"hasNextPage": False},
                    "nodes": [
                        {
                            "severity": "CRITICAL",
                            "advisory": {
                                "ghsaId": "GHSA-jfh8-c2jp-5v3q",
                                "identifiers": [{"type": "CVE", "value": "CVE-2021-44228"}],
                                "cvss": {"score": 10, "vectorString": VECTOR},
                            },
                            "package": {"name": "org.apache.logging.log4j:log4j-core", "ecosystem": "MAVEN"},
                            "vulnerableVersionRange": ">= 2.0, < 2.15.0",
                            "firstPatchedVersion": {"identifier": "2.15.0"},
                        }
                    ],
                }
            }
        }

    monkeypatch.setenv("GITHUB_TOKEN", "synthetic-test-token")
    monkeypatch.setattr(analysis, "_async_post", post)
    comps = [
        component(),
        component(6, name="Apache Log4j Core"),
        component(7, version="2.17.0", purl=LOG4J.replace("2.14.1", "2.17.0")),
    ]
    rows, errors, _ = asyncio.run(
        analysis.github_query_by_components(
            comps, replace(analysis.get_analysis_settings_multi(), source_cache_enabled=False)
        )
    )
    assert not errors and len(calls) == 1
    assert {r["component_id"] for r in rows} == {5, 6}
    assert all("CVE-2021-44228" in r["aliases"] and r["sources"] == ["GITHUB"] for r in rows)


def test_nvd_intelligence_fans_out_to_every_original_component(monkeypatch):
    from pathlib import Path

    from app.models import NvdLookupCache
    from app.services.nvd_enrichment_service import NvdEnrichmentService
    from app.settings import Settings
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    raw = json.loads(Path("tests/fixtures/nvd/cve_log4j_window.json").read_text())
    # Fixture is a complete NVD CVE object, independent of any database IDs.
    if "cve" in raw:
        raw = raw["cve"]

    class Client:
        calls = 0

        def request_nvd(self, params):
            self.calls += 1
            return {"vulnerabilities": [{"cve": raw}]}

    client = Client()
    engine = create_engine("sqlite:///:memory:")
    NvdLookupCache.__table__.create(engine)
    comps = [component(), component(6)]
    for c in comps:
        c.update(cpe="cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", cpe_source="sbom_provided")
    with Session(engine) as db:
        cfg = Settings(nvd_enabled=True)
        service = NvdEnrichmentService(db, cfg, client=client)
        first = service.enrich(comps, [])
        second = service.enrich(comps, [])
        assert {r["component"]["component_id"] for r in first["records"]} == {5, 6}
        assert {r["component"]["component_id"] for r in second["records"]} == {5, 6}
        assert client.calls == 1
    engine.dispose()


def test_alias_workflow_matching_never_crosses_occurrence_or_multicve():
    from types import SimpleNamespace

    from app.services.finding_metrics import remediation_for_finding, vex_for_finding

    finding = SimpleNamespace(
        component_id=5,
        vuln_id="CVE-2021-44228",
        aliases='["GHSA-jfh8-c2jp-5v3q"]',
        component_name="log4j-core",
        component_version="2.14.1",
        source_observations=[],
    )
    decision = SimpleNamespace(status="not_affected")
    assert vex_for_finding({(5, "GHSA-JFH8-C2JP-5V3Q"): decision}, finding) is decision
    assert vex_for_finding({(6, "CVE-2021-44228"): decision}, finding) is None
    remediation = object()
    assert (
        remediation_for_finding({("GHSA-jfh8-c2jp-5v3q", "log4j-core", "2.14.1"): remediation}, finding) is remediation
    )
    finding.aliases = '["CVE-2021-45046", "GHSA-jfh8-c2jp-5v3q"]'
    assert vex_for_finding({(5, "GHSA-JFH8-C2JP-5V3Q"): decision}, finding) is None


def test_run15_style_synthetic_before_after_metrics():
    # Historical counts are used only to shape this controlled fixture.
    baseline = [observation(vuln_id=f"CVE-2026-{10000 + i}") for i in range(42)]
    baseline.extend(
        observation(
            "OSV",
            component_id=None,
            component_name="org.apache.logging.log4j:log4j-core",
            component_version=None,
            vuln_id=f"CVE-2026-{10000 + i}",
        )
        for i in range(11, 82)
    )
    assert len(baseline) == 113 and sum(r["score"] is None for r in baseline) == 71
    corrected = copy.deepcopy(baseline)
    for i, row in enumerate(corrected[42:], start=11):
        row.update(component_id=5, component_name="log4j-core", component_version="2.14.1")
        if i < 74:
            rating = osv_assessment({"severity": [{"type": "CVSS_V3", "score": VECTOR}]})
            row.update(score=rating["score"], vector=rating["vector"], cvss_version=rating["version"])
    findings = reconcile(corrected)
    assert len(findings) == 82
    assert sum(len(f["source_observations"]) for f in findings) == 113
    assert sum(f["score"] is not None for f in findings) == 74
    assert sum(f["score"] is None for f in findings) == 8


def test_literal_purl_encoding_case_and_go_tags_remain_distinct():
    assert normalize_purl("pkg:generic/a%2541@1").normalized_purl == "pkg:generic/a%2541@1"
    assert normalize_purl("pkg:rpm/OpenSSL@1").normalized_purl == "pkg:rpm/OpenSSL@1"
    from app.normalization.component_normalizer import normalize_component

    comp = normalize_component(
        {"name": "Lib", "version": "v1.0.0", "purl": "pkg:golang/GitHub.com/Org/Lib@v1.0.0"}
    ).component
    assert comp["version"] == comp["normalized_version"] == "v1.0.0"


def test_numeric_cvss_overflow_is_unscored():
    assert numeric_score(10**1000) is None
    assert osv_assessment({"severity": ["malformed", {"type": "CVSS_V3", "score": "NaN"}]}) is None


def test_risk_aggregation_preserves_separate_occurrences(monkeypatch):
    from app.models import AnalysisFinding
    from app.services import risk_score

    monkeypatch.setattr(risk_score, "lookup_kev_set_memoized", lambda *args: set())
    monkeypatch.setattr(risk_score, "get_epss_scores_memoized", lambda *args: {})
    rows = [
        AnalysisFinding(
            analysis_run_id=1,
            component_id=cid,
            vuln_id="CVE-2021-44228",
            source="NVD",
            score=10,
            severity="CRITICAL",
            component_name="log4j-core",
            component_version="2.14.1",
        )
        for cid in (5, 6)
    ]
    result = risk_score.score_findings(None, rows)
    assert result["total_risk_score"] == 20
    assert {c["component_id"] for c in result["components"]} == {5, 6}


def test_persistence_allows_same_cve_cpe_on_distinct_components(reconciliation_db):
    from app.models import AnalysisFinding
    from app.services.analysis_service import persist_analysis_run
    from app.services.sbom_service import _upsert_components

    db = reconciliation_db
    sbom = seed_sbom(db, "same-cpe-different-occurrences")
    cpe = "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
    source = [
        {"name": "log4j-core", "version": "2.14.1", "purl": LOG4J, "bom_ref": ref, "cpe": cpe} for ref in ("a", "b")
    ]
    maps = _upsert_components(db, sbom, source)
    components = [{**comp, "component_id": maps["bom_ref"][comp["bom_ref"]].id} for comp in source]
    findings = [
        observation(component_id=c["component_id"], sbom_id=sbom.id, cpe=cpe, bom_ref=c["bom_ref"]) for c in components
    ]
    run = persist_analysis_run(
        db,
        sbom,
        {"total_findings": 2, "findings": findings},
        components,
        "FINDINGS",
        "NVD",
        "2026-10-15T00:00:00Z",
        "2026-10-15T00:00:01Z",
        1000,
    )
    db.flush()
    rows = db.query(AnalysisFinding).filter_by(analysis_run_id=run.id).all()
    assert len(rows) == run.total_findings == 2
    assert len({r.component_id for r in rows}) == len({r.reconciliation_key for r in rows}) == 2
