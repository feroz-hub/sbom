'use client';

import { useAiSettings } from '@/hooks/useAiFix';
import { BudgetCapsForm } from './BudgetCapsForm';
import { ProviderSelect } from './ProviderSelect';
import { UsageMetrics } from './UsageMetrics';

interface AiSettingsProps {
  /** Default provider name from server config — drives the "default" badge. */
  defaultProvider?: string;
  /** When false, the section renders a disabled-state notice. */
  enabled?: boolean;
}

/**
 * Settings → AI section.
 *
 * Phase 4 §4.1 (Integration 3). Read-only summary of providers, budget
 * caps, and usage telemetry. Inline editing (write API keys, edit caps)
 * is intentionally Phase 5 scope.
 */
export function AiSettings({ defaultProvider = 'anthropic', enabled = true }: AiSettingsProps) {
  const { providers, usage, isLoading, isError } = useAiSettings({ enabled });

  if (!enabled) {
    return (
      <section
        id="ai"
        className="space-y-4"
        aria-labelledby="ai-settings-heading"
      >
        <h2 id="ai-settings-heading" className="text-lg font-semibold text-hcl-navy">
          AI configuration
        </h2>
        <p className="rounded-lg border border-border-subtle bg-surface p-4 text-sm text-hcl-muted">
          AI fix generation is not enabled for this deployment. Set
          ``AI_FIXES_ENABLED=true`` in the environment to make the surface
          available; the kill-switch (``AI_FIXES_KILL_SWITCH=true``)
          overrides this regardless.
        </p>
      </section>
    );
  }

  return (
    <section id="ai" className="space-y-4" aria-labelledby="ai-settings-heading">
      <h2 id="ai-settings-heading" className="text-lg font-semibold text-hcl-navy">
        AI configuration
      </h2>

      {isError ? (
        <p className="rounded-lg border border-red-300 bg-red-50 p-4 text-sm text-red-800" role="alert">
          Could not load AI settings. The backend may be unreachable or AI
          telemetry endpoints are restricted.
        </p>
      ) : null}

      <ProviderSelect providers={providers ?? []} defaultProvider={defaultProvider} />
      <BudgetCapsForm usage={usage} />
      <UsageMetrics usage={usage} isLoading={isLoading} />
    </section>
  );
}
