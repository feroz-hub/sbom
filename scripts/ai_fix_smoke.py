#!/usr/bin/env python3
"""Phase 2 quality-review smoke script.

Runs the AI fix orchestrator against five hand-built grounding contexts
that mirror the five canonical examples in the Phase 2 prompt §8:

  1. Critical, KEV-listed, fix available
  2. Medium severity, fix available, low EPSS
  3. High severity, no fix available
  4. Critical, KEV, no fix available (worst case)
  5. Low severity, fix available — defer-tier

Usage::

    # Set the provider you want to exercise. Defaults to the registry's
    # configured default (typically Anthropic).
    export ANTHROPIC_API_KEY=sk-...
    python scripts/ai_fix_smoke.py
    # Or specify a different provider explicitly:
    python scripts/ai_fix_smoke.py --provider openai

This script bypasses the DB cache + ledger so each run hits the real
provider — Phase 2 §6 expects the owner to review three real outputs
before greenlighting Phase 3.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.ai.grounding import ComponentRef, FixVersionRef, GroundingContext
from app.ai.prompts import system_prompt, user_prompt
from app.ai.providers.base import LlmRequest
from app.ai.registry import get_registry
from app.ai.schemas import AiFixBundle, bundle_json_schema


def _example_1_critical_kev_with_fix() -> GroundingContext:
    return GroundingContext(
        cve_id="CVE-2021-44832",
        aliases=["GHSA-jfh8-c2jp-5v3q"],
        component=ComponentRef(
            name="org.apache.logging.log4j:log4j-core",
            version="2.16.0",
            ecosystem="Maven",
            purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.16.0",
            cpe="cpe:2.3:a:apache:log4j:2.16.0:*:*:*:*:*:*:*",
        ),
        cve_summary_from_db=(
            "Apache Log4j2 vulnerable to RCE via JDBC Appender when "
            "attacker controls Thread Context."
        ),
        severity="critical",
        cvss_v3_score=9.0,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H",
        cwe_ids=["CWE-502"],
        epss_score=0.97,
        epss_percentile=1.0,
        kev_listed=True,
        kev_due_date=date(2022, 6, 30),
        fix_versions=[
            FixVersionRef(ecosystem="Maven", package="org.apache.logging.log4j:log4j-core", fixed_in="2.17.1"),
            FixVersionRef(ecosystem="Maven", package="org.apache.logging.log4j:log4j-core", fixed_in="2.12.4"),
            FixVersionRef(ecosystem="Maven", package="org.apache.logging.log4j:log4j-core", fixed_in="2.3.2"),
        ],
        references=["https://logging.apache.org/log4j/2.x/security.html"],
        sources_used=["nvd", "kev", "epss", "fix_version_data"],
    )


def _example_2_medium_with_fix() -> GroundingContext:
    return GroundingContext(
        cve_id="CVE-2024-35195",
        component=ComponentRef(
            name="requests",
            version="2.31.0",
            ecosystem="PyPI",
            purl="pkg:pypi/requests@2.31.0",
        ),
        cve_summary_from_db=(
            "When making requests through a Requests Session, if the first request "
            "is made with verify=False, subsequent requests to the same host will "
            "continue to ignore cert verification."
        ),
        severity="medium",
        cvss_v3_score=5.4,
        cwe_ids=["CWE-670"],
        epss_score=0.0008,
        epss_percentile=0.08,
        kev_listed=False,
        fix_versions=[FixVersionRef(ecosystem="PyPI", package="requests", fixed_in="2.32.0")],
        sources_used=["nvd", "epss", "fix_version_data"],
    )


def _example_3_high_no_fix() -> GroundingContext:
    return GroundingContext(
        cve_id="CVE-2024-99001",
        component=ComponentRef(
            name="some-abandoned-pkg",
            version="1.2.3",
            ecosystem="npm",
            purl="pkg:npm/some-abandoned-pkg@1.2.3",
        ),
        cve_summary_from_db=(
            "Prototype pollution in some-abandoned-pkg allows remote code execution. "
            "Package has not been updated in over 24 months."
        ),
        severity="high",
        cvss_v3_score=7.8,
        epss_score=0.35,
        epss_percentile=0.85,
        kev_listed=False,
        fix_versions=[],
        sources_used=["nvd", "epss"],
    )


def _example_4_critical_kev_no_fix() -> GroundingContext:
    return GroundingContext(
        cve_id="CVE-2024-99002",
        component=ComponentRef(
            name="niche-lib",
            version="0.4.1",
            ecosystem="npm",
            purl="pkg:npm/niche-lib@0.4.1",
        ),
        cve_summary_from_db=(
            "Unauthenticated remote code execution in niche-lib via crafted URL "
            "fragment. No upstream maintainer response."
        ),
        severity="critical",
        cvss_v3_score=9.8,
        epss_score=0.95,
        epss_percentile=0.99,
        kev_listed=True,
        kev_due_date=date(2024, 12, 31),
        fix_versions=[],
        sources_used=["nvd", "epss", "kev"],
    )


def _example_5_low_defer() -> GroundingContext:
    return GroundingContext(
        cve_id="CVE-2023-99005",
        component=ComponentRef(
            name="some-pkg",
            version="1.0.0",
            ecosystem="PyPI",
            purl="pkg:pypi/some-pkg@1.0.0",
        ),
        cve_summary_from_db=(
            "Information disclosure in error-handling path under specific configurations."
        ),
        severity="low",
        cvss_v3_score=3.7,
        epss_score=0.0001,
        epss_percentile=0.01,
        kev_listed=False,
        fix_versions=[FixVersionRef(ecosystem="PyPI", package="some-pkg", fixed_in="1.0.1")],
        sources_used=["nvd", "epss", "fix_version_data"],
    )


EXAMPLES = [
    ("ex1_critical_kev_with_fix", _example_1_critical_kev_with_fix),
    ("ex2_medium_with_fix", _example_2_medium_with_fix),
    ("ex3_high_no_fix", _example_3_high_no_fix),
    ("ex4_critical_kev_no_fix", _example_4_critical_kev_no_fix),
    ("ex5_low_defer", _example_5_low_defer),
]


async def _run_one(provider, ctx: GroundingContext) -> dict:
    schema = bundle_json_schema()
    sys_p = system_prompt()
    usr_p = user_prompt(grounding_json=ctx.model_dump_for_prompt(), schema=schema)
    req = LlmRequest(
        system=sys_p,
        user=usr_p,
        response_schema=schema,
        max_output_tokens=1024,
        temperature=0.2,
        request_id=f"smoke-{ctx.cve_id}",
        purpose="fix_bundle",
    )
    resp = await provider.generate(req)
    text = resp.text.strip()
    parsed = resp.parsed
    bundle: dict | None = None
    if isinstance(parsed, dict):
        try:
            bundle = AiFixBundle.model_validate(parsed).model_dump(mode="json")
        except Exception as exc:
            print(f"  ! schema validation failed: {exc}")
    if bundle is None:
        try:
            obj = json.loads(text)
            bundle = AiFixBundle.model_validate(obj).model_dump(mode="json")
        except Exception as exc:
            print(f"  ! parse failed: {exc}")
    return {
        "cve_id": ctx.cve_id,
        "component": ctx.component.model_dump(mode="json"),
        "kev_listed": ctx.kev_listed,
        "fix_versions_count": len(ctx.fix_versions),
        "provider": resp.provider,
        "model": resp.model,
        "input_tokens": resp.usage.input_tokens,
        "output_tokens": resp.usage.output_tokens,
        "cost_usd": resp.usage.cost_usd,
        "latency_ms": resp.latency_ms,
        "raw_text": text,
        "bundle": bundle,
    }


async def main() -> int:
    ap = argparse.ArgumentParser(description="Phase 2 LLM quality review smoke")
    ap.add_argument("--provider", default=None, help="Provider name (defaults to registry default)")
    ap.add_argument("--out", default="audit/ai_fix_smoke_outputs.json", help="Where to write the JSON report")
    args = ap.parse_args()

    registry = get_registry()
    provider = registry.get(args.provider) if args.provider else registry.get_default()
    print(f"== Provider: {provider.name} model={provider.default_model}")

    results = []
    total_cost = 0.0
    for label, factory in EXAMPLES:
        ctx = factory()
        print(f"-- {label} ({ctx.cve_id} on {ctx.component.name}@{ctx.component.version})")
        try:
            r = await _run_one(provider, ctx)
        except Exception as exc:  # noqa: BLE001 — smoke script
            print(f"  !! provider call failed: {exc}")
            continue
        total_cost += r["cost_usd"]
        results.append({"label": label, **r})
        print(
            f"  ✓ {r['provider']}/{r['model']}  "
            f"in={r['input_tokens']} out={r['output_tokens']} "
            f"${r['cost_usd']:.5f}  {r['latency_ms']}ms"
        )

    out_path = ROOT / args.out
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2, sort_keys=True))
    print(f"\nWrote {len(results)} outputs → {out_path}")
    print(f"Total cost: ${total_cost:.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
