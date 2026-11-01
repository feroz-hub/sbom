"""SBO-99: real SBOM orchestration with synthetic OpenAI inference."""

import json

import httpx
import pytest
from app.ai.cost import BudgetCaps, BudgetGuard
from app.ai.fix_generator import AiFixGenerator
from app.ai.providers.base import LlmRequest
from app.ai.providers.openai import OpenAiProvider
from app.ai.registry import ProviderRegistry
from app.ai.schemas import AiFixResult
from app.db import SessionLocal
from app.models import AiUsageLog, AnalysisFinding
from app.services.validation_repair_service import AiRepairSuggestion
from sqlalchemy import select

from tests.ai.fixtures import EX1_CRITICAL_KEV_WITH_FIX_BUNDLE
from tests.ai.test_copilot_effective_config import _enabled_db_settings as enabled_settings  # noqa: F401
from tests.ai.test_fix_generator import _seeded as seeded_findings  # noqa: F401
from tests.ai.test_openai_modern import response

MODELS = ["gpt-4o", "gpt-4o-mini", "gpt-5-2025-08-07", "gpt-6-luna", "gpt-6.1-terra", "gpt-6-sol", "gpt-6.1-sol"]


def registry_for(provider):
    registry = ProviderRegistry(configs=[], default_provider="openai")
    registry.register_instance(provider)
    return registry


@pytest.mark.asyncio
@pytest.mark.parametrize("model", MODELS)
async def test_real_fix_generation_and_usage_ledger_with_modern_profiles(request, model):
    seed = request.getfixturevalue("seeded_findings")
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json=response(model, json.dumps(EX1_CRITICAL_KEV_WITH_FIX_BUNDLE)))
        )
    ) as client:
        provider = OpenAiProvider(api_key="synthetic-only", default_model=model, client_factory=lambda: client)
        with SessionLocal() as db:
            finding = db.get(AnalysisFinding, seed["kev"])
            result = await AiFixGenerator(db, registry=registry_for(provider)).generate_for_finding(finding)
            assert isinstance(result, AiFixResult)
            assert result.bundle.upgrade_command.target_version == "2.17.1"
            row = db.scalars(select(AiUsageLog).where(AiUsageLog.model == model)).one()
            assert row.output_tokens == 125 and row.cost_usd > 0


@pytest.mark.parametrize("model", MODELS)
def test_real_copilot_supplied_evidence_and_accounting(client, monkeypatch, request, model):
    request.getfixturevalue("enabled_settings")
    seen = []

    def handler(req):
        body = json.loads(req.content)
        seen.append(body)
        return httpx.Response(
            200, json=response(model, "Review the supplied findings and verify available fixed versions.")
        )

    provider = OpenAiProvider(
        api_key="synthetic-only",
        default_model=model,
        client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    monkeypatch.setattr("app.ai.copilot.get_registry", lambda db=None: registry_for(provider))
    result = client.post(
        "/api/ai/copilot/ask", json={"question": "Explain dependency risk using only the supplied SBOM evidence."}
    )
    assert result.status_code == 200, result.text
    assert result.json()["model"] == model
    assert result.json()["cost_usd"] > 0
    messages = seen[0].get("input", seen[0].get("messages"))
    assert "snapshot" in messages[0]["content"].lower()


@pytest.mark.asyncio
@pytest.mark.parametrize("model", MODELS)
async def test_validation_repair_schema_round_trip_remains_advisory(model):
    suggestion = {
        "summary": "Correct the synthetic component version.",
        "risk": "low",
        "patches": [],
        "requires_user_review": True,
    }

    def repair_handler(req):
        body = json.loads(req.content)
        modern = "input" in body
        fmt = body["text"]["format"] if modern else body["response_format"]
        assert fmt == {"type": "json_object"}  # JSON patch value is Any.
        messages = body["input"] if modern else body["messages"]
        assert "requires_user_review" in messages[0]["content"]
        return httpx.Response(200, json=response(model, json.dumps(suggestion)))

    async with httpx.AsyncClient(transport=httpx.MockTransport(repair_handler)) as client:
        provider = OpenAiProvider(api_key="synthetic-only", default_model=model, client_factory=lambda: client)
        result = await provider.generate(
            LlmRequest(
                system="Return only JSON repair advice. Never apply changes.",
                user='Synthetic invalid SBOM: {"component":{"version":null}}',
                request_id="repair-sbo99",
                response_schema=AiRepairSuggestion.model_json_schema(),
                max_output_tokens=2000,
            )
        )
    validated = AiRepairSuggestion.model_validate(result.parsed)
    assert validated.requires_user_review is True
    assert validated.patches == []


@pytest.mark.asyncio
async def test_incomplete_fix_is_charged_without_caching_or_fallback(request):
    seed = request.getfixturevalue("seeded_findings")
    model = "gpt-6.1-sol"
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json=response(model, "", status="incomplete")))
    ) as client:
        provider = OpenAiProvider(api_key="synthetic-only", default_model=model, client_factory=lambda: client)
        guard = BudgetGuard(BudgetCaps(per_request_usd=1, per_scan_usd=1, per_day_org_usd=1))
        with SessionLocal() as db:
            finding = db.get(AnalysisFinding, seed["kev"])
            result = await AiFixGenerator(db, registry=registry_for(provider), budget=guard).generate_for_finding(
                finding
            )
            assert not isinstance(result, AiFixResult)
            row = db.scalars(select(AiUsageLog).where(AiUsageLog.model == model)).one()
            assert row.output_tokens == 125 and row.cost_usd > 0


@pytest.mark.asyncio
@pytest.mark.parametrize("purpose", ["component_intelligence", "vulnerability_explanation", "vex_assistance"])
async def test_evidence_grounded_advisory_prompts_do_not_make_vex_decisions(purpose):
    # These are provider-contract scenarios, not claims of dedicated product
    # features: this checkout exposes Copilot, fixes and validation repair.
    seen = []
    evidence = {"component": "synthetic-package@1.0", "vulnerability": "CVE-2099-9001", "fixed_versions": ["1.1"]}

    def handler(req):
        seen.append(json.loads(req.content))
        return httpx.Response(
            200, json=response("gpt-6-luna", "Review synthetic-package 1.1 and validate applicability manually.")
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = OpenAiProvider(api_key="synthetic-only", default_model="gpt-6-luna", client_factory=lambda: client)
        result = await provider.generate(
            LlmRequest(
                system="Use supplied evidence only. Advise; never decide VEX applicability.",
                user=json.dumps(evidence),
                request_id="advisory-sbo99",
                purpose=purpose,
            )
        )
    assert "manually" in result.text
    assert json.loads(seen[0]["input"][1]["content"]) == evidence
    assert "never decide VEX" in seen[0]["input"][0]["content"]
