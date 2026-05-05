'use client';

import { Sparkles } from 'lucide-react';

interface AiFixGenerateButtonProps {
  /** Optional cost estimate (e.g. "~$0.005") shown in the helper text. */
  costEstimate?: string;
  /** Optional latency estimate (e.g. "3–8 seconds"). */
  timeEstimate?: string;
  /** Provider name for the helper line. */
  providerLabel?: string;
  onGenerate: () => void;
  loading?: boolean;
  errorMessage?: string;
}

/**
 * Empty-state CTA for the AI remediation tab.
 *
 * Phase 4 §4.4 hard rules:
 *   * Show provider name up front (trust hinges on it).
 *   * Surface cost estimate before any LLM call.
 *   * Loading state communicates which provider is being asked.
 */
export function AiFixGenerateButton({
  costEstimate,
  timeEstimate,
  providerLabel,
  onGenerate,
  loading,
  errorMessage,
}: AiFixGenerateButtonProps) {
  return (
    <div className="flex flex-col items-start gap-2 rounded-lg border border-dashed border-border bg-surface-muted p-4">
      <button
        type="button"
        onClick={onGenerate}
        disabled={loading}
        className="inline-flex items-center gap-2 rounded-md bg-primary px-3 py-2 text-sm font-medium text-white shadow-elev-1 hover:bg-hcl-dark disabled:cursor-progress disabled:opacity-70"
      >
        <Sparkles className="h-4 w-4" aria-hidden />
        {loading
          ? `Asking ${providerLabel ?? 'provider'}…`
          : 'Generate AI remediation'}
      </button>
      <p className="text-xs text-hcl-muted">
        {providerLabel ? <>Provider: {providerLabel}. </> : null}
        {costEstimate ? <>Estimated cost {costEstimate}. </> : null}
        {timeEstimate ? <>Typical latency {timeEstimate}.</> : null}
      </p>
      {errorMessage ? (
        <p className="text-xs text-red-700" role="alert">
          {errorMessage}
        </p>
      ) : null}
    </div>
  );
}
