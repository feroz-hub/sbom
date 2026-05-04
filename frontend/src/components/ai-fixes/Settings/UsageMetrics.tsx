'use client';

import type { AiUsageSummary } from '@/types/ai';

interface UsageMetricsProps {
  usage: AiUsageSummary | undefined;
  isLoading: boolean;
}

function formatUsd(usd: number | null | undefined): string {
  if (usd == null) return '—';
  if (usd === 0) return '$0.00';
  if (usd < 0.01) return '<$0.01';
  return `$${usd.toFixed(2)}`;
}

function formatRatio(ratio: number): string {
  return `${(ratio * 100).toFixed(1)}%`;
}

/**
 * Cost dashboard tile shown on the Settings → AI page.
 *
 * Mirrors the wireframe in Phase 4 §4.1 (Integration 3) — totals,
 * cache-hit ratio, daily-budget headroom, top providers and purposes.
 */
export function UsageMetrics({ usage, isLoading }: UsageMetricsProps) {
  if (isLoading || !usage) {
    return (
      <div className="rounded-lg border border-border-subtle bg-surface p-4 text-sm text-hcl-muted">
        Loading usage metrics…
      </div>
    );
  }

  return (
    <section className="space-y-4 rounded-lg border border-border-subtle bg-surface p-4">
      <h3 className="text-sm font-semibold text-hcl-navy">Usage this month</h3>

      <dl className="grid grid-cols-2 gap-3 text-sm md:grid-cols-4">
        <div>
          <dt className="text-xs uppercase tracking-wide text-hcl-muted">Total cost</dt>
          <dd className="mt-1 font-metric text-lg tabular-nums text-hcl-navy">
            {formatUsd(usage.last_30_days.total_cost_usd)}
          </dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-wide text-hcl-muted">Spent today</dt>
          <dd className="mt-1 font-metric text-lg tabular-nums text-hcl-navy">
            {formatUsd(usage.spent_today_usd)}
          </dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-wide text-hcl-muted">Cache hit rate</dt>
          <dd className="mt-1 font-metric text-lg tabular-nums text-hcl-navy">
            {formatRatio(usage.last_30_days.cache_hit_ratio)}
          </dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-wide text-hcl-muted">Daily budget left</dt>
          <dd className="mt-1 font-metric text-lg tabular-nums text-hcl-navy">
            {formatUsd(usage.daily_remaining_usd)}
          </dd>
        </div>
      </dl>

      {usage.by_provider.length > 0 ? (
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wide text-hcl-muted">
            Cost by provider
          </h4>
          <ul className="mt-2 space-y-1 text-sm text-hcl-navy">
            {usage.by_provider.slice(0, 5).map((b) => (
              <li key={b.label} className="flex items-center justify-between">
                <span>{b.label}</span>
                <span className="font-metric tabular-nums text-hcl-muted">
                  {b.calls} calls · {formatUsd(b.cost_usd)}
                </span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {usage.by_purpose.length > 0 ? (
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wide text-hcl-muted">
            Cost by purpose
          </h4>
          <ul className="mt-2 space-y-1 text-sm text-hcl-navy">
            {usage.by_purpose.slice(0, 5).map((b) => (
              <li key={b.label} className="flex items-center justify-between">
                <span>{b.label.replace(/_/g, ' ')}</span>
                <span className="font-metric tabular-nums text-hcl-muted">
                  {b.calls} calls · {formatUsd(b.cost_usd)}
                </span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </section>
  );
}
