"""PR-1 foundation tests for the VEX Dashboard & Investigation workstream.

Covers the data layer only — model constraints, canonical identity, importer
provenance and document idempotency. Reconciliation itself lands in PR-2.

Spec: docs/requirements/vex-dashboard-investigation.md sections 5-10 and 33-36.
"""

import unittest

from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import (
    Base,
    SBOMComponent,
    SBOMSource,
    VexDocument,
    VexInvestigation,
    VexStatement,
)
from app.services.lifecycle.vex_provider import (
    apply_vex_override,
    document_source_hash,
    effective_status_for,
    import_vex_document,
)
from app.services.vex import (
    AnalyzerDetectionState,
    EffectiveVexStatus,
    ReconciliationStatus,
    canonical_vulnerability,
)
from app.services.vex.enums import MappingConfidence, VexMatchStrategy
from app.services.vex.identity import (
    canonical_for_finding,
    canonical_for_statement,
    parse_alias_column,
)


class _DbTestCase(unittest.TestCase):
    """Disposable in-memory database, never the application's engine."""

    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.db = Session(self.engine)
        self.sbom = SBOMSource(sbom_name="vex-foundation", sbom_data="{}", tenant_id=1)
        self.db.add(self.sbom)
        self.db.flush()
        self.component = SBOMComponent(
            sbom_id=self.sbom.id, name="openssl", version="1.1.1", tenant_id=1
        )
        self.other_component = SBOMComponent(
            sbom_id=self.sbom.id, name="openssl", version="3.0.8", tenant_id=1
        )
        self.db.add_all([self.component, self.other_component])
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def make_context(self, **overrides):
        values = {
            "tenant_id": 1,
            "sbom_id": self.sbom.id,
            "component_id": self.component.id,
            "canonical_vulnerability_id": "CVE-2026-4001",
            "effective_status": EffectiveVexStatus.UNDER_INVESTIGATION.value,
            "reconciliation_status": ReconciliationStatus.ANALYZER_ONLY.value,
            "unresolved_discriminator": "",
            "first_seen_at": "2026-09-24T00:00:00Z",
            "last_seen_at": "2026-09-24T00:00:00Z",
            "created_at": "2026-09-24T00:00:00Z",
        }
        values.update(overrides)
        row = VexInvestigation(**values)
        self.db.add(row)
        return row


class CanonicalIdentityTests(unittest.TestCase):
    """VEX-CTX-002 — canonical identity and alias resolution."""

    def test_ghsa_finding_resolves_to_its_cve_alias__VEX_CTX_002(self):
        resolved = canonical_vulnerability(
            "GHSA-abcd-1234-5678", aliases=["CVE-2026-4001", "OSV-2026-99"]
        )
        self.assertEqual(resolved.canonical_id, "CVE-2026-4001")
        self.assertIn("GHSA-ABCD-1234-5678", resolved.aliases)
        self.assertIn("OSV-2026-99", resolved.aliases)
        self.assertNotIn("CVE-2026-4001", resolved.aliases)
        self.assertTrue(resolved.is_supported)

    def test_osv_identifier_resolves_to_cve_alias__VEX_CTX_002(self):
        self.assertEqual(
            canonical_vulnerability("OSV-2026-1234", aliases=["CVE-2026-4001"]).canonical_id,
            "CVE-2026-4001",
        )

    def test_advisory_without_a_cve_keeps_its_own_id__VEX_CTX_002(self):
        resolved = canonical_vulnerability("GHSA-abcd-1234-5678")
        self.assertEqual(resolved.canonical_id, "GHSA-ABCD-1234-5678")
        self.assertEqual(resolved.aliases, ())
        self.assertTrue(resolved.is_supported)

    def test_unrecognised_identifier_is_a_controlled_result__VEX_CTX_002(self):
        resolved = canonical_vulnerability("VENDOR-XYZ-1")
        self.assertEqual(resolved.canonical_id, "VENDOR-XYZ-1")
        self.assertFalse(resolved.is_supported)

    def test_alias_column_parsing_is_permissive(self):
        self.assertEqual(parse_alias_column('["CVE-2026-1", " "]'), ["CVE-2026-1"])
        self.assertEqual(parse_alias_column("not json"), [])
        self.assertEqual(parse_alias_column(None), [])
        self.assertEqual(parse_alias_column('{"a": 1}'), [])

    def test_finding_and_statement_adapters(self):
        finding = type("F", (), {"vuln_id": "GHSA-abcd-1234-5678", "aliases": '["CVE-2026-4001"]'})()
        self.assertEqual(canonical_for_finding(finding).canonical_id, "CVE-2026-4001")
        statement = type("S", (), {"vulnerability_id": "VENDOR-1", "cve_id": "CVE-2026-4001"})()
        self.assertEqual(canonical_for_statement(statement).canonical_id, "CVE-2026-4001")

    def test_aliases_json_round_trips(self):
        resolved = canonical_vulnerability("GHSA-abcd-1234-5678", aliases=["CVE-2026-4001"])
        self.assertIn("GHSA-ABCD-1234-5678", resolved.aliases_json)


class EffectiveStatusTests(unittest.TestCase):
    """VEX-STAT-001 and spec section 8 — four statuses, unknown folded in."""

    def test_only_four_canonical_statuses_exist__VEX_STAT_001(self):
        self.assertEqual(
            {s.value for s in EffectiveVexStatus},
            {"AFFECTED", "NOT_AFFECTED", "FIXED", "UNDER_INVESTIGATION"},
        )

    def test_unknown_maps_to_under_investigation__section_8(self):
        self.assertEqual(effective_status_for("unknown"), "UNDER_INVESTIGATION")
        self.assertEqual(effective_status_for(None), "UNDER_INVESTIGATION")
        self.assertEqual(effective_status_for("anything-unexpected"), "UNDER_INVESTIGATION")

    def test_known_statuses_map_one_to_one(self):
        self.assertEqual(effective_status_for("affected"), "AFFECTED")
        self.assertEqual(effective_status_for("not_affected"), "NOT_AFFECTED")
        self.assertEqual(effective_status_for("fixed"), "FIXED")
        self.assertEqual(effective_status_for("under_investigation"), "UNDER_INVESTIGATION")

    def test_six_reconciliation_states_exist__VEX_REC_001(self):
        self.assertEqual(
            {s.value for s in ReconciliationStatus},
            {
                "MATCHED",
                "ANALYZER_ONLY",
                "VEX_ONLY",
                "CONFLICT_REVIEW_REQUIRED",
                "REVALIDATION_REQUIRED",
                "UNRESOLVED_MAPPING",
            },
        )

    def test_source_failure_states_are_distinct_from_not_detected__VEX_REC_004(self):
        self.assertEqual(
            {s.value for s in AnalyzerDetectionState},
            {"DETECTED", "NOT_DETECTED", "NOT_QUERIED", "SOURCE_UNAVAILABLE", "SOURCE_ERROR"},
        )

    def test_weak_strategies_are_flagged__VEX_MAP_001(self):
        from app.services.vex.enums import WEAK_MATCH_STRATEGIES

        self.assertIn(VexMatchStrategy.NAME_ONLY, WEAK_MATCH_STRATEGIES)
        self.assertIn(VexMatchStrategy.NAME_VERSION, WEAK_MATCH_STRATEGIES)
        self.assertNotIn(VexMatchStrategy.PURL, WEAK_MATCH_STRATEGIES)
        self.assertIn(MappingConfidence.UNRESOLVED, set(MappingConfidence))


class VexInvestigationModelTests(_DbTestCase):
    """VEX-CTX-001 and VEX-DATA-001 — context identity and constraints."""

    def test_same_cve_on_two_components_is_two_contexts__VEX_CTX_001(self):
        self.make_context(component_id=self.component.id)
        self.make_context(component_id=self.other_component.id)
        self.db.commit()
        self.assertEqual(self.db.query(VexInvestigation).count(), 2)

    def test_duplicate_context_is_rejected__VEX_CTX_001(self):
        self.make_context()
        self.db.commit()
        self.make_context()
        with self.assertRaises(IntegrityError):
            self.db.commit()
        self.db.rollback()

    def test_tenant_is_part_of_context_identity__VEX_SEC_002(self):
        """The same CVE/SBOM/component in another tenant is a separate context.

        Inserting tenant 2 rows through the application session is blocked by
        the write-side guard in ``app/db.py``, which is the behaviour we want,
        so identity is asserted against the constraint definition instead.
        """
        unique = next(
            c for c in VexInvestigation.__table__.constraints
            if c.__class__.__name__ == "UniqueConstraint"
        )
        self.assertEqual(
            list(unique.columns.keys()),
            [
                "tenant_id",
                "sbom_id",
                "component_key",
                "canonical_vulnerability_id",
                "unresolved_discriminator",
            ],
        )

    def test_unresolved_mappings_do_not_collide__VEX_MAP_001(self):
        """component_id IS NULL twice must not violate the unique key, and the
        discriminator must still stop a genuine duplicate."""
        self.make_context(
            component_id=None,
            unresolved_discriminator="stmt-1",
            reconciliation_status=ReconciliationStatus.UNRESOLVED_MAPPING.value,
        )
        self.make_context(
            component_id=None,
            unresolved_discriminator="stmt-2",
            reconciliation_status=ReconciliationStatus.UNRESOLVED_MAPPING.value,
        )
        self.db.commit()
        self.assertEqual(self.db.query(VexInvestigation).count(), 2)

        self.make_context(
            component_id=None,
            unresolved_discriminator="stmt-1",
            reconciliation_status=ReconciliationStatus.UNRESOLVED_MAPPING.value,
        )
        with self.assertRaises(IntegrityError):
            self.db.commit()
        self.db.rollback()

    def test_component_key_mirrors_component_id_on_write(self):
        row = self.make_context()
        self.db.commit()
        self.db.refresh(row)
        self.assertEqual(row.component_key, self.component.id)

        # A caller that bypasses assign_component must not corrupt identity.
        row.component_id = None
        self.db.commit()
        self.db.refresh(row)
        self.assertEqual(row.component_key, 0)

        row.assign_component(self.other_component.id)
        self.db.commit()
        self.db.refresh(row)
        self.assertEqual(row.component_key, self.other_component.id)

    def test_defaults_are_current_and_version_one__VEX_AUD_002(self):
        row = self.make_context()
        self.db.commit()
        self.db.refresh(row)
        self.assertTrue(row.is_current)
        self.assertEqual(row.row_version, 1)


class ImporterProvenanceTests(_DbTestCase):
    """VEX-STAT-002 / VEX-DATA-002 — native status survives normalization."""

    def _statements(self):
        return self.db.scalars(select(VexStatement).order_by(VexStatement.id)).all()

    def test_cyclonedx_false_positive_keeps_its_native_value__VEX_STAT_002(self):
        import_vex_document(
            self.db,
            self.sbom.id,
            {
                "bomFormat": "CycloneDX",
                "serialNumber": "urn:uuid:aaaa",
                "vulnerabilities": [
                    {
                        "id": "CVE-2026-4001",
                        "analysis": {"state": "false_positive", "justification": "not reachable"},
                        "affects": [{"ref": "openssl"}],
                    }
                ],
            },
        )
        statement = self._statements()[0]
        self.assertEqual(statement.source_status, "false_positive")
        self.assertEqual(statement.status, "not_affected")
        self.assertEqual(statement.normalized_status, "NOT_AFFECTED")
        self.assertEqual(statement.source_format, "cyclonedx")

    def test_cyclonedx_in_triage_normalizes_to_under_investigation__VEX_STAT_002(self):
        import_vex_document(
            self.db,
            self.sbom.id,
            {
                "bomFormat": "CycloneDX",
                "serialNumber": "urn:uuid:bbbb",
                "vulnerabilities": [
                    {"id": "CVE-2026-4002", "analysis": {"state": "in_triage"}, "affects": [{"ref": "openssl"}]}
                ],
            },
        )
        statement = self._statements()[0]
        self.assertEqual(statement.source_status, "in_triage")
        self.assertEqual(statement.normalized_status, "UNDER_INVESTIGATION")

    def test_openvex_records_its_format_and_native_status__VEX_STAT_002(self):
        import_vex_document(
            self.db,
            self.sbom.id,
            {
                "@id": "https://example.test/vex/1",
                "timestamp": "2026-09-01T00:00:00Z",
                "statements": [
                    {
                        "vulnerability": {"name": "CVE-2026-4003"},
                        "status": "not_affected",
                        "justification": "vulnerable_code_not_present",
                        "products": ["openssl"],
                    }
                ],
            },
        )
        statement = self._statements()[0]
        self.assertEqual(statement.source_format, "openvex")
        self.assertEqual(statement.source_status, "not_affected")
        self.assertEqual(statement.normalized_status, "NOT_AFFECTED")
        self.assertEqual(statement.asserted_at, "2026-09-01T00:00:00Z")

    def test_manual_override_is_tagged_as_manual__VEX_DATA_002(self):
        apply_vex_override(
            self.db,
            self.component.id,
            "CVE-2026-4004",
            {"status": "fixed", "reason": "patched", "fixed_version": "3.0.9"},
            changed_by="analyst",
        )
        statement = self._statements()[0]
        self.assertEqual(statement.source_format, "manual")
        self.assertEqual(statement.normalized_status, "FIXED")

    def test_not_affected_still_requires_evidence__VEX_VAL_001(self):
        with self.assertRaises(HTTPException):
            apply_vex_override(
                self.db,
                self.component.id,
                "CVE-2026-4005",
                {"status": "not_affected", "reason": "because"},
                changed_by="analyst",
            )

    def test_fixed_still_requires_remediation_evidence__VEX_VAL_002(self):
        with self.assertRaises(HTTPException):
            apply_vex_override(
                self.db,
                self.component.id,
                "CVE-2026-4006",
                {"status": "fixed", "reason": "trust me", "fixed_version": " "},
                changed_by="analyst",
            )


class DocumentIdempotencyTests(_DbTestCase):
    """VEX-ING-002 / VEX-ING-003 — stable identity, provenance, versioning."""

    DOCUMENT = {
        "@id": "https://example.test/vex/openssl",
        "version": "1",
        "timestamp": "2026-09-01T00:00:00Z",
        "statements": [
            {
                "vulnerability": {"name": "CVE-2026-4001"},
                "status": "not_affected",
                "justification": "vulnerable_code_not_present",
                "products": ["openssl"],
            }
        ],
    }

    def test_hash_ignores_key_order_and_whitespace__VEX_ING_002(self):
        self.assertEqual(
            document_source_hash({"a": 1, "b": [1, 2]}),
            document_source_hash({"b": [1, 2], "a": 1}),
        )
        self.assertNotEqual(document_source_hash({"a": 1}), document_source_hash({"a": 2}))

    def test_reimporting_the_same_document_is_a_no_op__VEX_ING_002(self):
        first = import_vex_document(self.db, self.sbom.id, self.DOCUMENT)
        self.assertFalse(first["already_imported"])
        self.assertEqual(first["statements_imported"], 1)

        second = import_vex_document(self.db, self.sbom.id, dict(reversed(list(self.DOCUMENT.items()))))
        self.assertTrue(second["already_imported"])
        self.assertEqual(second["statements_imported"], 0)
        self.assertEqual(second["document_id"], first["document_id"])

        self.assertEqual(self.db.query(VexDocument).count(), 1)
        self.assertEqual(self.db.query(VexStatement).count(), 1)

    def test_a_new_version_appends_and_supersedes__VEX_ING_002(self):
        first = import_vex_document(self.db, self.sbom.id, self.DOCUMENT)
        updated = {**self.DOCUMENT, "version": "2"}
        updated["statements"] = [{**self.DOCUMENT["statements"][0], "status": "affected"}]
        second = import_vex_document(self.db, self.sbom.id, updated)

        self.assertFalse(second["already_imported"])
        self.assertNotEqual(second["document_id"], first["document_id"])
        self.assertEqual(second["superseded_document_ids"], [first["document_id"]])

        prior = self.db.get(VexDocument, first["document_id"])
        self.assertEqual(prior.superseded_by_id, second["document_id"])
        # History is preserved, not overwritten.
        self.assertEqual(self.db.query(VexDocument).count(), 2)
        self.assertEqual(self.db.query(VexStatement).count(), 2)

    def test_provenance_is_captured__VEX_ING_003(self):
        result = import_vex_document(self.db, self.sbom.id, self.DOCUMENT)
        document = self.db.get(VexDocument, result["document_id"])
        self.assertEqual(document.source_document_id, "https://example.test/vex/openssl")
        self.assertEqual(document.source_document_version, "1")
        self.assertEqual(document.source_hash, document_source_hash(self.DOCUMENT))
        self.assertEqual(document.asserted_at, "2026-09-01T00:00:00Z")
        self.assertIsNone(document.superseded_by_id)


if __name__ == "__main__":
    unittest.main()
