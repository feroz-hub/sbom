"""Phase 5 schema loosening — case-insensitive enums, ignored extras,
sensible defaults for the secondary classification fields. Each test
locks one specific tolerance against one observed real-world quirk.
"""

from __future__ import annotations

import pytest
from app.ai.schemas import (
    AiFixBundle,
    DecisionRecommendation,
    RemediationProse,
    UpgradeCommand,
)
from pydantic import ValidationError

# ============================================================ RemediationProse


def test_remediation_prose_accepts_capitalised_enum() -> None:
    """Gemini sometimes returns ``"High"`` with a capital H."""
    p = RemediationProse(
        summary_in_context="A long enough summary in context to pass min_length.",
        exploitation_likelihood="High",  # capitalised
        recommended_path="Upgrade to fixed version.",
        confidence="Medium",  # capitalised
    )
    assert p.exploitation_likelihood == "high"
    assert p.confidence == "medium"


def test_remediation_prose_accepts_spaced_enum() -> None:
    """``"Actively Exploited"`` from a model that ignored the
    underscore instruction must still match."""
    p = RemediationProse(
        summary_in_context="A long enough summary in context to pass min_length.",
        exploitation_likelihood="Actively Exploited",
        recommended_path="Patch immediately.",
    )
    assert p.exploitation_likelihood == "actively_exploited"


def test_remediation_prose_accepts_hyphenated_enum() -> None:
    p = RemediationProse(
        summary_in_context="A long enough summary in context to pass min_length.",
        exploitation_likelihood="actively-exploited",
        recommended_path="Patch immediately.",
    )
    assert p.exploitation_likelihood == "actively_exploited"


def test_remediation_prose_defaults_when_classification_fields_omitted() -> None:
    p = RemediationProse(
        summary_in_context="A long enough summary in context to pass min_length.",
        recommended_path="Upgrade to fixed version.",
    )
    assert p.exploitation_likelihood == "moderate"
    assert p.confidence == "medium"


def test_remediation_prose_ignores_extra_fields() -> None:
    """Models occasionally include extra context (``"explanation"``,
    ``"references"``) the schema doesn't define — silently dropped."""
    p = RemediationProse(
        **{
            "summary_in_context": "A long enough summary in context to pass min_length.",
            "exploitation_likelihood": "high",
            "recommended_path": "Upgrade to fixed version.",
            "confidence": "high",
            "explanation": "should be ignored",  # type: ignore[arg-type]
            "references": ["a", "b"],  # type: ignore[arg-type]
        }
    )
    assert not hasattr(p, "explanation")


# ============================================================ UpgradeCommand


def test_upgrade_command_defaults_when_classification_fields_omitted() -> None:
    cmd = UpgradeCommand(
        ecosystem="maven",
        command="mvn versions:set -DnewVersion=2.17.1",
        target_version="2.17.1",
        rationale="Smallest semver-stable upgrade containing the fix.",
    )
    assert cmd.breaking_change_risk == "unknown"
    assert cmd.tested_against_data is False


def test_upgrade_command_normalises_breaking_change_risk_case() -> None:
    cmd = UpgradeCommand(
        ecosystem="maven",
        command="mvn versions:set -DnewVersion=2.17.1",
        target_version="2.17.1",
        rationale="Smallest semver-stable upgrade containing the fix.",
        breaking_change_risk="Major",  # capitalised
    )
    assert cmd.breaking_change_risk == "major"


# ============================================================ DecisionRecommendation


def test_decision_recommendation_defaults_when_classification_omitted() -> None:
    d = DecisionRecommendation(reasoning=["A substantive reasoning bullet."])
    assert d.priority == "scheduled"
    assert d.confidence == "medium"


def test_decision_recommendation_accepts_uppercase_citations() -> None:
    """Gemini occasionally returns ``"KEV"`` instead of ``"kev"``."""
    d = DecisionRecommendation(
        priority="urgent",
        reasoning=["Listed in CISA KEV as actively exploited."],
        citations=["KEV", "NVD", "epss"],  # mixed case
        confidence="high",
    )
    assert d.citations == ["kev", "nvd", "epss"]


def test_decision_recommendation_allows_empty_reasoning_list() -> None:
    """Phase 5: an omitted reasoning list is acceptable; the bundle is
    still useful with the defaulted priority."""
    d = DecisionRecommendation(priority="urgent", confidence="high")
    assert d.reasoning == []


# ============================================================ AiFixBundle (whole)


def test_full_bundle_rejects_extra_top_level_field() -> None:
    """End-to-end: generated bundles reject unmodeled top-level fields."""
    with pytest.raises(ValidationError):
        AiFixBundle.model_validate(
            {
                "remediation_prose": {
                    "summary_in_context": "A long enough summary in context to pass min_length.",
                    "exploitation_likelihood": "High",  # capitalised
                    "recommended_path": "Upgrade to fixed version.",
                    "confidence": "Medium",
                },
                "upgrade_command": {
                    "ecosystem": "maven",
                    "command": "mvn versions:set -DnewVersion=2.17.1",
                    "target_version": "2.17.1",
                    "rationale": "Smallest semver-stable upgrade containing the fix.",
                    "breaking_change_risk": "Minor",
                    "tested_against_data": True,
                },
                "decision_recommendation": {
                    "priority": "Urgent",
                    "reasoning": ["Listed in CISA KEV as actively exploited."],
                    "citations": ["KEV", "NVD"],
                    "confidence": "High",
                },
                "model_self_critique": "ignored",
            }
        )


def test_full_bundle_rejects_invalid_enum_value() -> None:
    """Loosening must NOT accept arbitrary strings — the strict
    schema still rules. ``"super-critical"`` is not a valid priority."""
    with pytest.raises(ValidationError):
        AiFixBundle.model_validate(
            {
                "remediation_prose": {
                    "summary_in_context": "A long enough summary in context to pass min_length.",
                    "exploitation_likelihood": "high",
                    "recommended_path": "Upgrade to fixed version.",
                },
                "upgrade_command": {
                    "ecosystem": "maven",
                    "command": "mvn versions:set",
                    "target_version": "2.17.1",
                    "rationale": "ok",
                    "tested_against_data": True,
                },
                "decision_recommendation": {
                    "priority": "super-critical",  # invalid
                    "reasoning": ["A substantive reasoning bullet."],
                },
            }
        )
