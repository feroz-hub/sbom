"""AI fix orchestrator — single entrypoint the API + Celery worker call.

Flow per finding:

  1. Build :class:`~app.ai.grounding.GroundingContext` from DB state.
  2. Compute the cache key.
  3. Read ``ai_fix_cache``. Hit → return immediately, log a cache-hit row
     in ``ai_usage_log`` (zero cost), bump ``last_accessed_at``.
  4. Miss → assemble :class:`~app.ai.providers.base.LlmRequest` with the
     bundle JSON schema attached.
  5. Pre-flight :class:`~app.ai.cost.BudgetGuard.check_request` using an
     estimated cost from prompt size + ``max_output_tokens``.
  6. Call the provider via :class:`~app.ai.registry.ProviderRegistry`.
  7. Parse the response into :class:`~app.ai.schemas.AiFixBundle` (one
     retry on parse failure with a stricter prompt addendum).
  8. **Post-validate** against the grounding — flip
     ``tested_against_data`` to ``False`` and ``breaking_change_risk`` to
     ``unknown`` if the model invented a fix version.
  9. Write the cache + ledger rows.
  10. Return :class:`AiFixResult`.

Errors are reported as :class:`~app.ai.schemas.AiFixError`, never raised.
The Phase 3 batch worker treats those as per-finding skips.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy.orm import Session

from ..models import AnalysisFinding
from ..settings import get_settings
from . import cache as cache_mod
from .cache_lock import CacheLock, get_cache_lock
from .cost import (
    BudgetCaps,
    BudgetGuard,
    estimate_cost_usd,
    estimate_tokens,
    write_usage_log_row,
)
from .grounding import GroundingContext, build_grounding_context
from .observability import (
    generate_span,
    log_ai_call,
    record_call,
)
from .prompts import PROMPT_VERSION, system_prompt, user_prompt
from .providers.base import (
    AiProviderError,
    BudgetExceededError,
    CircuitBreakerOpenError,
    LlmProvider,
    LlmRequest,
    ProviderUnavailableError,
)
from .registry import ProviderRegistry, get_registry
from .schemas import (
    AiFixBundle,
    AiFixError,
    AiFixResult,
    bundle_json_schema,
)

log = logging.getLogger("sbom.ai.fix_generator")


# ---------------------------------------------------------------------------
# Result envelope for the caller
# ---------------------------------------------------------------------------


def _budget_caps_from_settings() -> BudgetCaps:
    s = get_settings()
    return BudgetCaps(
        per_request_usd=float(s.ai_budget_per_request_usd) if s.ai_budget_per_request_usd is not None else None,
        per_scan_usd=float(s.ai_budget_per_scan_usd) if s.ai_budget_per_scan_usd is not None else None,
        per_day_org_usd=float(s.ai_budget_per_day_org_usd) if s.ai_budget_per_day_org_usd is not None else None,
    )


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class AiFixGenerator:
    """Single entrypoint for AI fix generation.

    Constructor dependencies are injectable so Phase 2 unit tests can pass a
    fake registry / fake provider without monkeypatching anything.
    """

    def __init__(
        self,
        db: Session,
        *,
        registry: ProviderRegistry | None = None,
        budget: BudgetGuard | None = None,
        cache_lock: CacheLock | None = None,
    ) -> None:
        self._db = db
        self._registry = registry or get_registry(db)
        self._budget = budget or BudgetGuard(_budget_caps_from_settings())
        # Generation lock — prevents two concurrent batches from making
        # duplicate LLM calls for the same cache key. Falls back to a
        # process-local lock when Redis is unreachable; documented in
        # the runbook as a multi-worker caveat.
        self._cache_lock = cache_lock or get_cache_lock()

    @property
    def registry(self) -> ProviderRegistry:
        return self._registry

    @property
    def budget(self) -> BudgetGuard:
        return self._budget

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def generate_for_finding(
        self,
        finding: AnalysisFinding,
        *,
        provider_name: str | None = None,
        force_refresh: bool = False,
        scan_id: int | None = None,
    ) -> AiFixResult | AiFixError:
        """Generate (or fetch from cache) the AI fix bundle for one finding."""
        s = get_settings()
        if s.ai_fixes_kill_switch:
            return AiFixError(
                finding_id=finding.id,
                vuln_id=finding.vuln_id or "",
                component_name=finding.component_name or "",
                component_version=finding.component_version or "",
                error_code="provider_unavailable",
                message="AI fixes kill switch is enabled.",
            )

        try:
            ctx = build_grounding_context(finding, db=self._db)
        except Exception as exc:  # noqa: BLE001
            log.warning("ai.generate.grounding_failed: finding_id=%s err=%s", finding.id, exc)
            return AiFixError(
                finding_id=finding.id,
                vuln_id=finding.vuln_id or "",
                component_name=finding.component_name or "",
                component_version=finding.component_version or "",
                error_code="grounding_missing",
                message=str(exc),
            )

        cache_key = cache_mod.make_cache_key(
            vuln_id=ctx.cve_id,
            component_name=ctx.component.name,
            component_version=ctx.component.version,
        )

        if not force_refresh:
            hit = cache_mod.read_cache(self._db, cache_key=cache_key)
            if hit is not None:
                cache_mod.touch_last_accessed(self._db, cache_key=cache_key)
                hit_request_id = str(uuid.uuid4())
                # Ledger row for the hit — zero cost, marks the call.
                write_usage_log_row(
                    self._db,
                    request_id=hit_request_id,
                    provider=hit.metadata.provider_used,
                    model=hit.metadata.model_used,
                    purpose="fix_bundle",
                    finding_cache_key=cache_key,
                    input_tokens=0,
                    output_tokens=0,
                    cost_usd=0.0,
                    latency_ms=0,
                    cache_hit=True,
                )
                # Telemetry + audit log for the cache hit.
                record_call(
                    provider=hit.metadata.provider_used,
                    model=hit.metadata.model_used,
                    purpose="fix_bundle",
                    outcome="cache_hit",
                    latency_seconds=0.0,
                    cost_usd=0.0,
                    cache_hit=True,
                )
                log_ai_call(
                    request_id=hit_request_id,
                    provider=hit.metadata.provider_used,
                    model=hit.metadata.model_used,
                    purpose="fix_bundle",
                    finding_cache_key=cache_key,
                    input_tokens=0,
                    output_tokens=0,
                    cost_usd=0.0,
                    latency_ms=0,
                    cache_hit=True,
                    outcome="cache_hit",
                    response_text=None,
                )
                return hit.model_copy(update={"finding_id": finding.id})

        # Cache miss — pick provider, build request, enforce budget, call.
        try:
            provider = (
                self._registry.get(provider_name) if provider_name else self._registry.get_default()
            )
        except ProviderUnavailableError as exc:
            return self._error(finding, ctx, "provider_unavailable", str(exc))

        # Cross-batch dedup: hold a lock keyed on the cache key while we
        # generate. Two concurrent batches that scope-overlap on this
        # finding will hit this gate; the second waits, re-checks the
        # cache after acquiring the lock, and returns the first batch's
        # result instead of paying twice for the same LLM call.
        async with self._cache_lock.acquire(cache_key) as acquired:
            if acquired and not force_refresh:
                # Re-check the cache: another worker may have written
                # while we waited on the lock.
                hit2 = cache_mod.read_cache(self._db, cache_key=cache_key)
                if hit2 is not None:
                    cache_mod.touch_last_accessed(self._db, cache_key=cache_key)
                    return hit2.model_copy(update={"finding_id": finding.id})

            # Either we acquired the lock and are the generator, or we
            # timed out waiting and proceed best-effort. The latter is
            # rare (30s default) and at worst pays for a duplicate call;
            # we never block the user beyond the lock TTL.
            return await self._generate_uncached(
                finding=finding,
                ctx=ctx,
                cache_key=cache_key,
                provider=provider,
                scan_id=scan_id,
            )

    async def generate_for_findings(
        self,
        findings: Sequence[AnalysisFinding],
        *,
        provider_name: str | None = None,
        force_refresh: bool = False,
        scan_id: int | None = None,
    ) -> list[AiFixResult | AiFixError]:
        """Sequential wrapper used by tests + simple callers.

        The Phase 3 batch worker re-implements this with bounded
        concurrency via :class:`asyncio.Semaphore`. Keeping this method
        sequential here means the orchestrator stays small and the
        concurrency primitives live in one place (the worker).
        """
        out: list[AiFixResult | AiFixError] = []
        for f in findings:
            out.append(
                await self.generate_for_finding(
                    f,
                    provider_name=provider_name,
                    force_refresh=force_refresh,
                    scan_id=scan_id,
                )
            )
        return out

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _generate_uncached(
        self,
        *,
        finding: AnalysisFinding,
        ctx: GroundingContext,
        cache_key: str,
        provider: LlmProvider,
        scan_id: int | None,
    ) -> AiFixResult | AiFixError:
        schema = bundle_json_schema()
        sys_p = system_prompt()
        usr_p = user_prompt(grounding_json=ctx.model_dump_for_prompt(), schema=schema)
        request_id = str(uuid.uuid4())
        # Pre-flight cost estimation.
        max_output_tokens = 1024
        estimated_input = estimate_tokens(sys_p) + estimate_tokens(usr_p)
        estimated_cost = estimate_cost_usd(
            provider=provider.name,
            model=provider.default_model,
            input_tokens=estimated_input,
            output_tokens=max_output_tokens,
            is_local=getattr(provider, "is_local", False),
        )
        try:
            self._budget.check_request(estimated_usd=estimated_cost, scan_id=scan_id)
        except BudgetExceededError as exc:
            self._log_failed_call(
                request_id=request_id,
                provider=provider.name,
                model=provider.default_model,
                cache_key=cache_key,
                error=f"budget_exceeded:{exc.scope}",
            )
            return self._error(finding, ctx, "budget_exceeded", str(exc))

        req = LlmRequest(
            system=sys_p,
            user=usr_p,
            response_schema=schema,
            max_output_tokens=max_output_tokens,
            temperature=0.2,
            request_id=request_id,
            purpose="fix_bundle",
        )

        t0 = time.perf_counter()
        try:
            with generate_span(
                provider=provider.name,
                model=provider.default_model,
                purpose="fix_bundle",
                request_id=request_id,
                cache_hit=False,
            ):
                resp = await provider.generate(req)
        except CircuitBreakerOpenError as exc:
            self._log_failed_call(
                request_id=request_id,
                provider=provider.name,
                model=provider.default_model,
                cache_key=cache_key,
                error=f"circuit_breaker_open:{exc}",
            )
            return self._error(finding, ctx, "circuit_breaker_open", str(exc))
        except AiProviderError as exc:
            self._log_failed_call(
                request_id=request_id,
                provider=provider.name,
                model=provider.default_model,
                cache_key=cache_key,
                error=f"provider_error:{exc}",
            )
            return self._error(finding, ctx, "provider_unavailable", str(exc))

        latency_ms = int((time.perf_counter() - t0) * 1000)

        bundle, parse_error = self._parse_bundle(resp.text, resp.parsed)
        if bundle is None and parse_error is not None:
            # Single retry with stricter instructions (Phase 2 §3.4).
            log.info("ai.generate.parse_retry: finding=%s err=%s", finding.id, parse_error)
            retry_user = (
                usr_p
                + "\n\nYour previous response was not valid JSON conforming to the schema. "
                "Reply with the JSON only — no prose, no code fences."
            )
            retry_req = req.model_copy(update={"user": retry_user, "request_id": str(uuid.uuid4())})
            try:
                resp = await provider.generate(retry_req)
            except (AiProviderError, CircuitBreakerOpenError) as exc:
                self._log_failed_call(
                    request_id=retry_req.request_id,
                    provider=provider.name,
                    model=provider.default_model,
                    cache_key=cache_key,
                    error=f"retry_failed:{exc}",
                )
                return self._error(finding, ctx, "schema_parse_failed", str(exc))
            latency_ms += int((time.perf_counter() - t0) * 1000)
            bundle, parse_error = self._parse_bundle(resp.text, resp.parsed)

        if bundle is None:
            self._log_failed_call(
                request_id=request_id,
                provider=provider.name,
                model=provider.default_model,
                cache_key=cache_key,
                error=f"schema_parse_failed:{parse_error}",
            )
            return self._error(
                finding,
                ctx,
                "schema_parse_failed",
                parse_error or "model returned non-conforming JSON",
            )

        validated = self._post_validate(bundle, ctx)

        # Record actual cost + write ledger row.
        self._budget.record(actual_usd=resp.usage.cost_usd, scan_id=scan_id)
        write_usage_log_row(
            self._db,
            request_id=request_id,
            provider=provider.name,
            model=resp.model,
            purpose="fix_bundle",
            finding_cache_key=cache_key,
            input_tokens=resp.usage.input_tokens,
            output_tokens=resp.usage.output_tokens,
            cost_usd=resp.usage.cost_usd,
            latency_ms=latency_ms,
            cache_hit=False,
            error=None,
        )
        # Telemetry + audit log for the successful generation. Body is
        # never logged — only the SHA-256 (Phase 5 §5.2 hard rule).
        record_call(
            provider=provider.name,
            model=resp.model,
            purpose="fix_bundle",
            outcome="ok",
            latency_seconds=latency_ms / 1000.0,
            cost_usd=resp.usage.cost_usd,
            cache_hit=False,
        )
        log_ai_call(
            request_id=request_id,
            provider=provider.name,
            model=resp.model,
            purpose="fix_bundle",
            finding_cache_key=cache_key,
            input_tokens=resp.usage.input_tokens,
            output_tokens=resp.usage.output_tokens,
            cost_usd=resp.usage.cost_usd,
            latency_ms=latency_ms,
            cache_hit=False,
            outcome="ok",
            response_text=resp.text,
        )

        result = cache_mod.write_cache(
            self._db,
            cache_key=cache_key,
            vuln_id=ctx.cve_id,
            component_name=ctx.component.name,
            component_version=ctx.component.version,
            bundle=validated,
            provider_used=provider.name,
            model_used=resp.model,
            total_cost_usd=resp.usage.cost_usd,
            kev_listed=ctx.kev_listed,
        )
        return result.model_copy(update={"finding_id": finding.id})

    # ------------------------------------------------------------------
    # Parsing + post-validation
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_bundle(text: str, parsed: dict[str, Any] | None) -> tuple[AiFixBundle | None, str | None]:
        """Parse the LLM output into an :class:`AiFixBundle`."""
        candidates: list[Any] = []
        if isinstance(parsed, dict):
            candidates.append(parsed)
        if text:
            stripped = text.strip()
            if stripped.startswith("```"):
                # Strip any code fences the model snuck in.
                stripped = stripped.strip("`")
                if stripped.lower().startswith("json"):
                    stripped = stripped[4:]
            try:
                candidates.append(json.loads(stripped))
            except json.JSONDecodeError:
                pass

        last_err: str | None = "no JSON candidates produced"
        for cand in candidates:
            if not isinstance(cand, dict):
                continue
            try:
                return AiFixBundle.model_validate(cand), None
            except Exception as exc:  # noqa: BLE001 — surface the validation error
                last_err = str(exc)
                continue
        return None, last_err

    @staticmethod
    def _post_validate(bundle: AiFixBundle, ctx: GroundingContext) -> AiFixBundle:
        """Demote ``tested_against_data`` if the model invented a version.

        Hard rule from prompt §2.2: only versions present in
        ``ctx.fix_versions`` may carry ``tested_against_data=True``. If the
        model returned a version that isn't in the data, we don't reject —
        we surface the model's suggestion but flip the flag so the UI
        shows the "inferred" caveat.
        """
        allowed = {fv.fixed_in for fv in ctx.fix_versions if fv.fixed_in}
        target = bundle.upgrade_command.target_version.strip()
        invented = bool(allowed) and target.lower() not in {a.lower() for a in allowed if a} and target.lower() != "n/a"
        no_data = not allowed and target.lower() != "n/a"
        if invented or no_data:
            bundle = bundle.model_copy(
                update={
                    "upgrade_command": bundle.upgrade_command.model_copy(
                        update={
                            "tested_against_data": False,
                            "breaking_change_risk": "unknown",
                        }
                    )
                }
            )
        # actively_exploited requires kev_listed
        if bundle.remediation_prose.exploitation_likelihood == "actively_exploited" and not ctx.kev_listed:
            bundle = bundle.model_copy(
                update={
                    "remediation_prose": bundle.remediation_prose.model_copy(
                        update={"exploitation_likelihood": "high"}
                    )
                }
            )
        # citations subset of sources_used
        allowed_citations = set(ctx.sources_used)
        cleaned = [c for c in bundle.decision_recommendation.citations if c in allowed_citations]
        if cleaned != bundle.decision_recommendation.citations:
            bundle = bundle.model_copy(
                update={
                    "decision_recommendation": bundle.decision_recommendation.model_copy(
                        update={"citations": cleaned}
                    )
                }
            )
        return bundle

    # ------------------------------------------------------------------
    # Error helpers
    # ------------------------------------------------------------------

    def _error(
        self,
        finding: AnalysisFinding,
        ctx: GroundingContext,
        code: str,
        message: str,
    ) -> AiFixError:
        return AiFixError(
            finding_id=finding.id,
            vuln_id=ctx.cve_id,
            component_name=ctx.component.name,
            component_version=ctx.component.version,
            error_code=code,  # type: ignore[arg-type]
            message=message,
        )

    def _log_failed_call(
        self,
        *,
        request_id: str,
        provider: str,
        model: str,
        cache_key: str,
        error: str,
    ) -> None:
        write_usage_log_row(
            self._db,
            request_id=request_id,
            provider=provider,
            model=model,
            purpose="fix_bundle",
            finding_cache_key=cache_key,
            input_tokens=0,
            output_tokens=0,
            cost_usd=0.0,
            latency_ms=0,
            cache_hit=False,
            error=error[:500],
        )
        # Telemetry + audit: bucket the outcome by failure family so the
        # dashboard can show "12 budget halts, 3 provider errors today"
        # without parsing free-form messages.
        outcome = _classify_failure(error)
        record_call(
            provider=provider,
            model=model,
            purpose="fix_bundle",
            outcome=outcome,
            latency_seconds=0.0,
            cost_usd=0.0,
            cache_hit=False,
        )
        log_ai_call(
            request_id=request_id,
            provider=provider,
            model=model,
            purpose="fix_bundle",
            finding_cache_key=cache_key,
            input_tokens=0,
            output_tokens=0,
            cost_usd=0.0,
            latency_ms=0,
            cache_hit=False,
            outcome=outcome,
            response_text=None,
            error=error,
        )


def _classify_failure(error: str) -> str:
    """Bucket a raw error string into a stable outcome label.

    Inspecting the prefix is good enough — :meth:`AiFixGenerator._log_failed_call`
    is called from a handful of well-known sites that prefix their messages
    with the family (``budget_exceeded:``, ``circuit_breaker_open:``,
    ``provider_error:``, ``schema_parse_failed:``, ``retry_failed:``).
    """
    if not error:
        return "provider_error"
    head = error.split(":", 1)[0]
    if head == "budget_exceeded":
        return "budget_exceeded"
    if head == "circuit_breaker_open":
        return "circuit_open"
    if head == "schema_parse_failed":
        return "schema_parse_failed"
    if head in {"retry_failed", "provider_error"}:
        return "provider_error"
    return "provider_error"


__all__ = [
    "AiFixError",
    "AiFixGenerator",
    "AiFixResult",
    "PROMPT_VERSION",
]
