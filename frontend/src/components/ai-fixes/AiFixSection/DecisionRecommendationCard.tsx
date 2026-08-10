'use client';

import type { AiDecisionRecommendation } from '@/types/ai';

interface DecisionRecommendationCardProps {
  decision: AiDecisionRecommendation;
}

const PRIORITY_PRESENTATION: Record<
  AiDecisionRecommendation['priority'],
  { label: string; className: string }
> = {
  urgent: { label: 'Priority: urgent', className: 'border-red-300 bg-red-50 text-red-800' },
  soon: { label: 'Priority: soon', className: 'border-orange-300 bg-orange-50 text-orange-800' },
  scheduled: { label: 'Priority: scheduled', className: 'border-amber-300 bg-amber-50 text-amber-800' },
  defer: { label: 'Priority: defer', className: 'border-emerald-300 bg-emerald-50 text-emerald-800' },
};

export function DecisionRecommendationCard({ decision }: DecisionRecommendationCardProps) {
  const priority = PRIORITY_PRESENTATION[decision.priority];

  return (
    <section
      className="rounded-lg border border-border-subtle bg-surface-muted p-4"
      aria-labelledby="ai-decision-heading"
    >
      <h4
        id="ai-decision-heading"
        className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-hcl-muted"
      >
        Decision recommendation
      </h4>

      <div className="mb-3 flex flex-wrap items-center gap-2 text-xs">
        <span className={`inline-flex items-center rounded-full border px-2 py-0.5 font-medium ${priority.className}`}>
          {priority.label}
        </span>
        <span className="rounded-full border border-border-subtle bg-surface px-2 py-0.5 font-medium text-hcl-muted">
          Confidence: {decision.confidence}
        </span>
      </div>

      <ul className="mb-3 list-inside list-disc space-y-1 text-sm text-hcl-navy">
        {decision.reasoning.map((bullet, i) => (
          <li key={i}>{bullet}</li>
        ))}
      </ul>

      {decision.citations.length > 0 ? (
        <p className="mb-2 text-xs text-hcl-muted">
          <span className="font-medium">Citations:</span>{' '}
          {decision.citations
            .map((c) => c.replace(/_/g, ' ').toUpperCase().replace('FIX VERSION DATA', 'OSV/GHSA fix data'))
            .join(', ')}
        </p>
      ) : null}

      {decision.caveats.length > 0 ? (
        <div className="mt-2 rounded-md border border-amber-200 bg-amber-50 p-3">
          <p className="text-[11px] font-semibold uppercase tracking-wide text-amber-800">
            Caveats
          </p>
          <ul className="list-inside list-disc text-xs text-amber-900">
            {decision.caveats.map((c, i) => (
              <li key={i}>{c}</li>
            ))}
          </ul>
        </div>
      ) : null}
    </section>
  );
}
