'use client';

import { ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react';
import type { AiConfidenceTier } from '@/types/ai';

interface OverallConfidenceBadgeProps {
  confidence: AiConfidenceTier;
}

/**
 * Color-coded presentation for the model's self-assessed confidence in the
 * whole response. Mirrors the tier palette used elsewhere in the AI-fix UI
 * (emerald = good, amber = caution, red = low) so the signal reads at a
 * glance: emerald/high = trust it, red/low = read the caveats first.
 */
function presentation(c: AiConfidenceTier): {
  label: string;
  Icon: typeof ShieldCheck;
  className: string;
} {
  switch (c) {
    case 'high':
      return {
        label: 'High',
        Icon: ShieldCheck,
        className: 'border-emerald-300 bg-emerald-50 text-emerald-800',
      };
    case 'low':
      return {
        label: 'Low',
        Icon: ShieldAlert,
        className: 'border-red-300 bg-red-50 text-red-800',
      };
    case 'medium':
    default:
      return {
        label: 'Medium',
        Icon: ShieldQuestion,
        className: 'border-amber-300 bg-amber-50 text-amber-800',
      };
  }
}

/**
 * Prominent, top-of-section indicator of how much the model trusts its own
 * end-to-end answer. Rendered as the first element of the result stack so a
 * reader can calibrate before reading the detail. This is the response-level
 * signal; the muted per-section "Confidence: …" pills inside
 * ``RemediationProse`` / ``DecisionRecommendationCard`` remain unchanged.
 */
export function OverallConfidenceBadge({ confidence }: OverallConfidenceBadgeProps) {
  const { label, Icon, className } = presentation(confidence);
  return (
    <div
      data-testid="ai-overall-confidence"
      className="flex items-center justify-between gap-2 rounded-lg border border-border-subtle bg-surface-muted px-3 py-2"
    >
      <span className="text-[11px] font-semibold uppercase tracking-wider text-hcl-muted">
        Overall AI confidence
      </span>
      <span
        className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-xs font-semibold ${className}`}
        aria-label={`Overall AI confidence: ${label}`}
      >
        <Icon className="h-4 w-4" aria-hidden />
        {label}
      </span>
    </div>
  );
}
