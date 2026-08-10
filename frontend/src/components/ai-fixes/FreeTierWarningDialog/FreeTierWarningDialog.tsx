'use client';

import { AlertTriangle, X } from 'lucide-react';
import type { AiBatchDurationEstimate } from '@/types/ai';
import { EstimatedTimeline } from './EstimatedTimeline';

interface FreeTierWarningDialogProps {
  open: boolean;
  estimate: AiBatchDurationEstimate | null;
  onContinue: () => void;
  onCancel: () => void;
  /** Optional: a paid alternative the user can switch to in Settings. */
  paidAlternative?: AiBatchDurationEstimate | null;
}

/**
 * Phase 3 §3.5 — "this batch will take ~12 minutes" warning.
 *
 * Fires before the user clicks Generate when the active provider is a
 * free tier and the duration estimate exceeds 5 minutes
 * (``warning_recommended=true`` from the estimator).
 *
 * Three options: continue, switch (deeplink to Settings → AI), cancel.
 */
export function FreeTierWarningDialog({
  open,
  estimate,
  onContinue,
  onCancel,
  paidAlternative,
}: FreeTierWarningDialogProps) {
  if (!open || !estimate) return null;

  return (
    <div
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="ai-free-tier-warning-heading"
      className="fixed inset-0 z-40 flex items-start justify-center bg-black/40 px-4 py-12"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onCancel();
      }}
    >
      <div className="w-full max-w-md rounded-lg border border-amber-200 bg-surface p-6 shadow-card">
        <header className="mb-3 flex items-start justify-between">
          <h2
            id="ai-free-tier-warning-heading"
            className="flex items-center gap-2 text-lg font-semibold text-amber-900"
          >
            <AlertTriangle className="h-5 w-5" aria-hidden />
            Free tier rate limit detected
          </h2>
          <button
            type="button"
            onClick={onCancel}
            aria-label="Close dialog"
            className="rounded-md p-1 text-hcl-muted hover:bg-surface-muted"
          >
            <X className="h-4 w-4" aria-hidden />
          </button>
        </header>

        <p className="text-sm text-hcl-navy">
          Generating fixes for{' '}
          <span className="font-medium">{estimate.findings_to_generate}</span>{' '}
          new findings on{' '}
          <span className="font-medium">{estimate.provider}</span>{' '}
          ({estimate.tier} tier, {estimate.requests_per_minute.toFixed(0)} req/min).
        </p>

        <div className="mt-3 space-y-2">
          <p className="text-xs uppercase tracking-wide text-hcl-muted">Options</p>
          <div className="space-y-1">
            <EstimatedTimeline estimate={estimate} />
            {paidAlternative ? <EstimatedTimeline estimate={paidAlternative} /> : null}
          </div>
        </div>

        <footer className="mt-4 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
          <button
            type="button"
            onClick={onCancel}
            className="rounded-md border border-border-subtle bg-surface px-3 py-1.5 text-sm text-hcl-navy hover:bg-surface-muted"
          >
            Cancel
          </button>
          <a
            href="/settings/ai"
            className="rounded-md border border-primary bg-surface px-3 py-1.5 text-sm font-medium text-primary hover:bg-primary/5"
          >
            Switch provider
          </a>
          <button
            type="button"
            onClick={onContinue}
            className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white shadow-elev-1 hover:bg-hcl-dark"
          >
            Continue with {estimate.provider}
          </button>
        </footer>
      </div>
    </div>
  );
}
