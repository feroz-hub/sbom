'use client';

import { Loader2, Sparkles } from 'lucide-react';
import { useAiFix } from '@/hooks/useAiFix';
import type { AiFixError } from '@/types/ai';
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

const ERROR_MESSAGES: Record<AiFixError['error_code'], string> = {
  schema_parse_failed: 'The AI provider returned an unexpected response. Try regenerating.',
  provider_unavailable: 'The AI provider is unreachable. Try again or switch provider in Settings.',
  circuit_breaker_open: 'The AI provider is temporarily disabled after repeated failures. Try again in a minute.',
  budget_exceeded: 'Daily AI budget reached. Increase the cap in Settings or wait until tomorrow.',
  grounding_missing: 'No vulnerability data is available for this finding yet.',
  internal_error: 'Something went wrong while contacting the AI provider.',
};

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
  const { data, isFetching, isError, error, refetch, regenerate } = useAiFix(findingId, {
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

      {/* Loading skeleton (only when there's no prior data on first open). */}
      {isFetching && !result && !apiError ? (
        <div className="flex items-center gap-2 rounded-lg border border-dashed border-border bg-surface-muted p-4 text-sm text-hcl-muted">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
          <span>
            Asking {providerLabel ?? 'AI provider'}…
          </span>
        </div>
      ) : null}

      {/* Network-level error (HttpError thrown by the api client). */}
      {isError && !result && !apiError ? (
        <AiFixGenerateButton
          providerLabel={providerLabel}
          costEstimate={costEstimate}
          timeEstimate={timeEstimate}
          loading={isFetching}
          onGenerate={() => refetch()}
          errorMessage={(error as Error)?.message ?? 'Could not reach the API.'}
        />
      ) : null}

      {/* Structured backend error (status 200 with ``error`` populated). */}
      {apiError && !result ? (
        <AiFixGenerateButton
          providerLabel={providerLabel}
          costEstimate={costEstimate}
          timeEstimate={timeEstimate}
          loading={regenerate.isPending}
          onGenerate={() => regenerate.mutate()}
          errorMessage={ERROR_MESSAGES[apiError.error_code] ?? apiError.message}
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
