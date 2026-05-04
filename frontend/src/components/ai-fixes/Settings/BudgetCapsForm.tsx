'use client';

import type { AiUsageSummary } from '@/types/ai';

interface BudgetCapsFormProps {
  usage: AiUsageSummary | undefined;
}

function formatUsd(value: number | null | undefined): string {
  if (value == null) return '—';
  return `$${value.toFixed(2)}`;
}

/**
 * Read-only display of the configured budget caps.
 *
 * Phase 4 ships the read-only view; inline editing of caps is Phase 5
 * scope (it requires a write endpoint + audit trail and is not on the
 * Phase 4 deliverables list).
 */
export function BudgetCapsForm({ usage }: BudgetCapsFormProps) {
  const caps = usage?.budget_caps_usd;

  return (
    <section className="rounded-lg border border-border-subtle bg-surface p-4">
      <h3 className="mb-3 text-sm font-semibold text-hcl-navy">Budget caps</h3>
      <dl className="grid grid-cols-1 gap-2 text-sm md:grid-cols-3">
        <div>
          <dt className="text-xs uppercase tracking-wide text-hcl-muted">Per request</dt>
          <dd className="mt-1 font-metric tabular-nums text-hcl-navy">
            {formatUsd(caps?.per_request_usd ?? null)}
          </dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-wide text-hcl-muted">Per scan</dt>
          <dd className="mt-1 font-metric tabular-nums text-hcl-navy">
            {formatUsd(caps?.per_scan_usd ?? null)}
          </dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-wide text-hcl-muted">Per day (org)</dt>
          <dd className="mt-1 font-metric tabular-nums text-hcl-navy">
            {formatUsd(caps?.per_day_org_usd ?? null)}
          </dd>
        </div>
      </dl>
      <p className="mt-3 text-xs text-hcl-muted">
        Caps are configured via ``AI_BUDGET_PER_REQUEST_USD`` /
        ``AI_BUDGET_PER_SCAN_USD`` / ``AI_BUDGET_PER_DAY_ORG_USD``
        environment variables. Hit caps trigger a ``paused_budget`` status
        on the active batch — increase the value or wait for the daily
        reset (UTC midnight).
      </p>
    </section>
  );
}
