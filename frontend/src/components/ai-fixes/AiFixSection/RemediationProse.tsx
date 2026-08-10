'use client';

import { Activity, AlertTriangle, ShieldCheck } from 'lucide-react';
import type { AiRemediationProse } from '@/types/ai';

interface RemediationProseProps {
  prose: AiRemediationProse;
}

function likelihoodPresentation(likelihood: AiRemediationProse['exploitation_likelihood']): {
  label: string;
  Icon: typeof Activity;
  className: string;
} {
  switch (likelihood) {
    case 'actively_exploited':
      return {
        label: 'Actively exploited',
        Icon: AlertTriangle,
        className: 'border-red-300 bg-red-50 text-red-800',
      };
    case 'high':
      return {
        label: 'High likelihood',
        Icon: AlertTriangle,
        className: 'border-orange-300 bg-orange-50 text-orange-800',
      };
    case 'moderate':
      return {
        label: 'Moderate likelihood',
        Icon: Activity,
        className: 'border-amber-300 bg-amber-50 text-amber-800',
      };
    case 'low':
      return {
        label: 'Low likelihood',
        Icon: ShieldCheck,
        className: 'border-emerald-300 bg-emerald-50 text-emerald-800',
      };
    case 'theoretical':
    default:
      return {
        label: 'Theoretical',
        Icon: ShieldCheck,
        className: 'border-slate-300 bg-slate-50 text-slate-700',
      };
  }
}

function confidenceBadge(c: AiRemediationProse['confidence']): string {
  switch (c) {
    case 'high':
      return 'Confidence: high';
    case 'medium':
      return 'Confidence: medium';
    case 'low':
    default:
      return 'Confidence: low';
  }
}

export function RemediationProse({ prose }: RemediationProseProps) {
  const { label, Icon, className } = likelihoodPresentation(prose.exploitation_likelihood);
  return (
    <section className="space-y-3" aria-labelledby="ai-prose-heading">
      <h4 id="ai-prose-heading" className="sr-only">
        AI remediation summary
      </h4>
      <p className="text-sm leading-relaxed text-hcl-navy">{prose.summary_in_context}</p>
      <p className="text-sm leading-relaxed text-hcl-navy">
        <span className="font-medium">Recommended path:</span> {prose.recommended_path}
      </p>
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span
          className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 font-medium ${className}`}
        >
          <Icon className="h-3.5 w-3.5" aria-hidden />
          {label}
        </span>
        <span className="rounded-full border border-border-subtle bg-surface px-2 py-0.5 font-medium text-hcl-muted">
          {confidenceBadge(prose.confidence)}
        </span>
      </div>
    </section>
  );
}
