"""Schema validation tests — the first line of the hallucination defence."""

from __future__ import annotations

import json

import pytest
from app.ai.schemas import (
    SCHEMA_VERSION,
    AiFixBundle,
    DecisionRecommendation,
    RemediationProse,
    UpgradeCommand,
    bundle_json_schema,
)
from pydantic import ValidationError

from tests.ai.fixtures import (
    EX1_CRITICAL_KEV_WITH_FIX_BUNDLE,
    EX2_MEDIUM_WITH_FIX_BUNDLE,
    EX3_HIGH_NO_FIX_BUNDLE,
)

# ============================================================ Canonical examples


def test_example_1_critical_kev_validates():
    bundle = AiFixBundle.model_validate(EX1_CRITICAL_KEV_WITH_FIX_BUNDLE)
    assert bundle.remediation_prose.exploitation_likelihood == "actively_exploited"
    assert bundle.upgrade_command.target_version == "2.17.1"
    assert bundle.upgrade_command.tested_against_data is True
    assert bundle.decision_recommendation.priority == "urgent"
    assert "kev" in bundle.decision_recommendation.citations


def test_example_2_medium_with_fix_validates():
    bundle = AiFixBundle.model_validate(EX2_MEDIUM_WITH_FIX_BUNDLE)
    assert bundle.upgrade_command.breaking_change_risk == "none"
    assert bundle.decision_recommendation.priority == "scheduled"


def test_example_3_high_no_fix_validates():
    bundle = AiFixBundle.model_validate(EX3_HIGH_NO_FIX_BUNDLE)
    assert bundle.upgrade_command.target_version == "n/a"
    assert bundle.upgrade_command.tested_against_data is False
    assert bundle.upgrade_command.breaking_change_risk == "unknown"
    assert len(bundle.decision_recommendation.caveats) == 2


# ============================================================ Negative paths


def test_extra_fields_rejected():
    bad = dict(EX1_CRITICAL_KEV_WITH_FIX_BUNDLE)
    bad["extra_field"] = "nope"
    with pytest.raises(ValidationError):
        AiFixBundle.model_validate(bad)


def test_invalid_priority_rejected():
    payload = dict(EX1_CRITICAL_KEV_WITH_FIX_BUNDLE)
    payload["decision_recommendation"] = dict(payload["decision_recommendation"])
    payload["decision_recommendation"]["priority"] = "asap"
    with pytest.raises(ValidationError):
        AiFixBundle.model_validate(payload)


def test_invalid_likelihood_rejected():
    payload = json.loads(json.dumps(EX1_CRITICAL_KEV_WITH_FIX_BUNDLE))
    payload["remediation_prose"]["exploitation_likelihood"] = "imminent"
    with pytest.raises(ValidationError):
        AiFixBundle.model_validate(payload)


def test_reasoning_must_be_substantive():
    payload = json.loads(json.dumps(EX1_CRITICAL_KEV_WITH_FIX_BUNDLE))
    payload["decision_recommendation"]["reasoning"] = ["ok", "ok"]
    with pytest.raises(ValidationError):
        AiFixBundle.model_validate(payload)


def test_summary_min_length_enforced():
    with pytest.raises(ValidationError):
        RemediationProse(
            summary_in_context="too short",
            exploitation_likelihood="low",
            recommended_path="upgrade soon",
            confidence="high",
        )


def test_decision_caveats_capped_to_three():
    rec = DecisionRecommendation(
        priority="soon",
        reasoning=["legitimate reasoning bullet"],
        citations=["nvd"],
        confidence="medium",
        caveats=["a" * 10, "b" * 10, "c" * 10, "d" * 10, "e" * 10],
    )
    assert len(rec.caveats) == 3


def test_upgrade_command_target_version_required():
    with pytest.raises(ValidationError):
        UpgradeCommand(
            ecosystem="PyPI",
            command="pip install foo",
            target_version="",
            rationale="x",
            breaking_change_risk="none",
            tested_against_data=False,
        )


# ============================================================ JSON Schema export


def test_bundle_json_schema_exports_three_keys():
    schema = bundle_json_schema()
    props = schema.get("properties") or {}
    assert set(props.keys()) == {
        "remediation_prose",
        "upgrade_command",
        "decision_recommendation",
    }


def test_schema_version_constant_stable():
    # Phase 2 ships at v1; bumping requires a cache invalidation review.
    assert SCHEMA_VERSION == 1
