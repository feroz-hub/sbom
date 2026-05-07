'use client';

import { Loader2, Sparkles } from 'lucide-react';
import { useAiFix } from '@/hooks/useAiFix';
import type { AiFixError } from '@/types/ai';
import { GENERATE_DISABLED_CODES } from '@/types/ai';
import { AiFixGenerateButton } from './AiFixGenerateButton';
import { AiFixMetadata } from './AiFixMetadata';
import { DecisionRecommendationCard } from './DecisionRecommendationCard';
import { RemediationProse } from './RemediationProse';
import { UpgradeCommandCard } from './UpgradeCommandCard';

interface AiFixSectionProps {
  findingId: number | null;
  /** When false, the section renders a flag-disabled banner instead of triggering. */
  enabled?: boolean;
  /** Display name + cost hint for the empty-state CTA. */
  providerLabel?: string;
  costEstimate?: string;
  timeEstimate?: string;
}

/**
 * Render copy for a structured backend error.
 *
 * Phase 5: each ``error_code`` gets a typed copy template that
 * interpolates the structured fields the backend now propagates
 * (``provider_name``, ``model_name``, ``retry_after_human``,
 * ``retry_after_seconds``, ``upstream_message``). The Generate button is
 * separately disabled per :data:`GENERATE_DISABLED_CODES` for codes that
 * cannot be resolved by clicking again.
 */
export function aiFixErrorCopy(err: AiFixError, providerLabelFallback?: string): string {
  const provider = err.provider_name ?? providerLabelFallback ?? 'the AI provider';
  const model = err.model_name ?? 'the configured model';
  const retryHuman = err.retry_after_human ?? null;
  const retrySec = err.retry_after_seconds ?? null;
  const upstream = err.upstream_message ?? err.message;

  switch (err.error_code) {
    case 'quota_exceeded':
      return `Daily quota exhausted for ${provider} (${model}). ${
        retryHuman ? `Resets ${retryHuman}, ` : ''
      }or switch provider in Settings.`;
    case 'rate_limited':
      return `Rate limit hit for ${provider}. ${
        retrySec ? `Retry in ${retrySec}s.` : 'Retry in a moment.'
      }`;
    case 'auth_failed':
      return `Invalid API key for ${provider}. Update in Settings.`;
    case 'model_not_found':
      return `Model ${model} not available. Update in Settings.`;
    case 'network_unreachable':
      return `Couldn't reach ${provider}. Check network or try again.`;
    case 'provider_down':
      return `${provider} is currently unavailable.`;
    case 'invalid_request':
      return `Request was rejected by ${provider}: ${upstream}`;
    case 'unknown':
      return `Unexpected error: ${upstream}`;
    // Legacy codes — kept stable for already-cached events.
    case 'schema_parse_failed':
      // The raw provider response is internal diagnostic data — it
      // belongs in ``ai_usage_log.error`` for operators, not in the
      // user modal. Earlier copy leaked it as "Response preview: …",
      // which surfaced quota prose (and any other provider noise)
      // verbatim to users.
      return 'The AI returned an unexpected response. Try regenerating, or switch provider in Settings.';
    case 'provider_unavailable':
      return 'The AI provider is unreachable. Try again or switch provider in Settings.';
    case 'circuit_breaker_open':
      return 'The AI provider is temporarily disabled after repeated failures. Try again in a minute.';
    case 'budget_exceeded':
      return 'Daily AI budget reached. Increase the cap in Settings or wait until tomorrow.';
    case 'grounding_missing':
      return 'No vulnerability data is available for this finding yet.';
    case 'internal_error':
      return 'Something went wrong while contacting the AI provider.';
    default: {
      // Defensive: future codes still render a useful message.
      const _exhaustive: never = err.error_code;
      return upstream || 'Unexpected error.';
    }
  }
}

/**
 * The "AI remediation" section embedded inside the CVE detail modal.
 *
 * Phase 4 §4.1 (Integration 1) — empty / generating / cached / error states
 * are explicit and accessible. Cached entries surface provenance up front
 * (Phase 4 §4.3); the `Regenerate` button is always one click away.
 */
export function AiFixSection({
  findingId,
  enabled = true,
  providerLabel,
  costEstimate = '~$0.005',
  timeEstimate = '3–8 seconds',
}: AiFixSectionProps) {
  const { data, isFetching, isError, error, refetch, generate, regenerate } = useAiFix(findingId, {
    enabled: enabled && findingId != null,
  });

  if (!enabled) {
    return (
      <section
        className="space-y-2 border-t border-border-subtle px-6 py-3"
        aria-labelledby="ai-fix-disabled-heading"
      >
        <h3
          id="ai-fix-disabled-heading"
          className="text-[11px] font-semibold uppercase tracking-wider text-hcl-muted"
        >
          AI remediation
        </h3>
        <p className="text-sm text-hcl-muted">
          AI remediation is not enabled for this deployment. Contact your administrator to flip the flag in Settings.
        </p>
      </section>
    );
  }

  const result = data?.result ?? null;
  const apiError = data?.error ?? null;
  // ``data === null`` means the read-only GET returned 404 (no cached
  // bundle). This is the idle empty state — show the Generate button
  // and wait for an explicit user click.
  const noCache = data === null;
  const generating = generate.isPending;

  return (
    <section
      className="space-y-3 border-t border-border-subtle px-6 py-3"
      aria-labelledby="ai-fix-heading"
      data-testid="ai-fix-section"
    >
      <header className="flex items-center justify-between">
        <h3
          id="ai-fix-heading"
          className="text-[11px] font-semibold uppercase tracking-wider text-hcl-muted"
        >
          <Sparkles className="mr-1 inline h-3.5 w-3.5 text-primary" aria-hidden />
          AI remediation
        </h3>
      </header>

      {/* Initial cache-check spinner (very short — just a DB read). */}
      {isFetching && !data && !isError ? (
        <div className="flex items-center gap-2 rounded-lg border border-dashed border-border bg-surface-muted p-4 text-sm text-hcl-muted">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
          <span>Checking for cached remediation…</span>
        </div>
      ) : null}

      {/* Generation in progress (user clicked Generate). */}
      {generating ? (
        <div className="flex items-center gap-2 rounded-lg border border-dashed border-border bg-surface-muted p-4 text-sm text-hcl-muted">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
          <span>Asking {providerLabel ?? 'AI provider'}…</span>
        </div>
      ) : null}

      {/* Idle empty state — no cached fix exists. */}
      {noCache && !generating ? (
        <AiFixGenerateButton
          providerLabel={providerLabel}
          costEstimate={costEstimate}
          timeEstimate={timeEstimate}
          loading={false}
          onGenerate={() => generate.mutate()}
          errorMessage={
            generate.isError ? (generate.error as Error)?.message : undefined
          }
        />
      ) : null}

      {/* Network-level error reading the cache. */}
      {isError && !data && !generating ? (
        <AiFixGenerateButton
          providerLabel={providerLabel}
          costEstimate={costEstimate}
          timeEstimate={timeEstimate}
          loading={isFetching}
          onGenerate={() => refetch()}
          errorMessage={(error as Error)?.message ?? 'Could not reach the API.'}
        />
      ) : null}

      {/* Structured backend error from a previous generation attempt. */}
      {apiError && !result ? (
        <AiFixGenerateButton
          providerLabel={apiError.provider_name ?? providerLabel}
          costEstimate={costEstimate}
          timeEstimate={timeEstimate}
          loading={regenerate.isPending}
          onGenerate={() => regenerate.mutate()}
          errorMessage={aiFixErrorCopy(apiError, providerLabel)}
          disabledByError={GENERATE_DISABLED_CODES.includes(apiError.error_code)}
        />
      ) : null}

      {/* Cached / freshly generated result. */}
      {result ? (
        <div className="space-y-4">
          <RemediationProse prose={result.bundle.remediation_prose} />
          <UpgradeCommandCard command={result.bundle.upgrade_command} />
          <DecisionRecommendationCard decision={result.bundle.decision_recommendation} />
          <AiFixMetadata
            metadata={result.metadata}
            onRegenerate={() => regenerate.mutate()}
            regenerating={regenerate.isPending}
          />
        </div>
      ) : null}
    </section>
  );
}
