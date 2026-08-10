'use client';

import { useQuery } from '@tanstack/react-query';
import { getAiTopCachedFixes, getAiUsageTrend } from '@/lib/api';
import { Sparkline } from '@/components/ui/Sparkline';
import type { AiUsageSummary } from '@/types/ai';

interface CostDashboardProps {
  usage: AiUsageSummary | undefined;
}

function formatUsd(usd: number | null | undefined): string {
  if (usd == null) return '—';
  if (usd === 0) return '$0.00';
  if (usd < 0.01) return '<$0.01';
  if (usd < 1) return `$${usd.toFixed(4)}`;
  return `$${usd.toFixed(2)}`;
}

function formatRatio(r: number): string {
  return `${(r * 100).toFixed(1)}%`;
}

/**
 * Cost dashboard — Phase 5 §5.3.
 *
 * Composes the trend sparkline + per-purpose / per-provider breakdowns +
 * top-20 most-expensive cache entries + cache-hit ratio + recent failures.
 * Reads from the read-only telemetry endpoints; no write surface (caps
 * editing is owner-controlled via env vars).
 */
export function CostDashboard({ usage }: CostDashboardProps) {
  const trend = useQuery({
    queryKey: ['ai-usage-trend', 30],
    queryFn: ({ signal }) => getAiUsageTrend({ days: 30 }, signal),
    refetchInterval: 60_000,
  });

  const topCached = useQuery({
    queryKey: ['ai-top-cached', 20],
    queryFn: ({ signal }) => getAiTopCachedFixes({ limit: 20 }, signal),
    refetchInterval: 5 * 60_000,
  });

  const trendCosts = trend.data?.points.map((p) => p.cost_usd) ?? [];
  const trendCalls = trend.data?.points.map((p) => p.calls) ?? [];

  return (
    <section className="space-y-4" aria-labelledby="ai-cost-dashboard-heading">
      <h2 id="ai-cost-dashboard-heading" className="text-lg font-semibold text-hcl-navy">
        Cost & usage
      </h2>

      {/* Headline tiles */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <KpiTile
          label="Today"
          value={formatUsd(usage?.spent_today_usd)}
          sub={
            usage?.daily_remaining_usd != null
              ? `${formatUsd(usage.daily_remaining_usd)} budget left`
              : 'no daily cap'
          }
        />
        <KpiTile
          label="Last 30 days"
          value={formatUsd(usage?.last_30_days.total_cost_usd)}
          sub={`${usage?.last_30_days.total_calls ?? 0} calls`}
        >
          {trendCosts.length > 1 ? (
            <Sparkline
              data={trendCosts}
              ariaLabel="30-day cost trend"
              color="var(--color-hcl-blue)"
            />
          ) : null}
        </KpiTile>
        <KpiTile
          label="Cache hit ratio"
          value={usage ? formatRatio(usage.last_30_days.cache_hit_ratio) : '—'}
          sub={`${usage?.last_30_days.total_cache_hits ?? 0} hits`}
        />
        <KpiTile
          label="Calls / day"
          value={trendCalls.length ? Math.round(trendCalls.reduce((a, b) => a + b, 0) / trendCalls.length).toString() : '—'}
          sub="30-day average"
        >
          {trendCalls.length > 1 ? (
            <Sparkline data={trendCalls} ariaLabel="30-day call volume trend" />
          ) : null}
        </KpiTile>
      </div>

      {/* Per-purpose / per-provider breakdowns */}
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <BreakdownTile
          title="Cost by purpose (30d)"
          rows={
            usage?.by_purpose.map((b) => ({
              label: b.label.replace(/_/g, ' '),
              calls: b.calls,
              cost_usd: b.cost_usd,
            })) ?? []
          }
        />
        <BreakdownTile
          title="Cost by provider (30d)"
          rows={
            usage?.by_provider.map((b) => ({
              label: b.label,
              calls: b.calls,
              cost_usd: b.cost_usd,
            })) ?? []
          }
        />
      </div>

      {/* Top-N expensive cache entries */}
      <section className="rounded-lg border border-border-subtle bg-surface p-4">
        <h3 className="mb-3 text-sm font-semibold text-hcl-navy">
          Most expensive cached fixes (top 20)
        </h3>
        {topCached.isLoading ? (
          <p className="text-sm text-hcl-muted">Loading…</p>
        ) : (topCached.data ?? []).length === 0 ? (
          <p className="text-sm text-hcl-muted">
            No cached AI fixes yet. Trigger a batch from a run page to populate this list.
          </p>
        ) : (
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase tracking-wide text-hcl-muted">
              <tr>
                <th scope="col" className="py-2">Component</th>
                <th scope="col" className="py-2">CVE</th>
                <th scope="col" className="py-2">Provider</th>
                <th scope="col" className="py-2 text-right">Cost</th>
              </tr>
            </thead>
            <tbody>
              {topCached.data?.map((item) => (
                <tr key={item.cache_key} className="border-t border-border-subtle">
                  <td className="py-2 font-mono text-xs">
                    {item.component_name}
                    <span className="text-hcl-muted">@{item.component_version}</span>
                  </td>
                  <td className="py-2 font-mono text-xs">{item.vuln_id}</td>
                  <td className="py-2 text-xs text-hcl-muted">
                    {item.provider_used}
                    <span className="ml-1 text-hcl-muted/70">({item.model_used})</span>
                  </td>
                  <td className="py-2 text-right font-metric tabular-nums">
                    {formatUsd(item.total_cost_usd)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </section>
  );
}


// ---------------------------------------------------------------------------


interface KpiTileProps {
  label: string;
  value: string;
  sub?: string;
  children?: React.ReactNode;
}

function KpiTile({ label, value, sub, children }: KpiTileProps) {
  return (
    <div className="rounded-lg border border-border-subtle bg-surface p-4">
      <p className="text-xs uppercase tracking-wide text-hcl-muted">{label}</p>
      <p className="mt-1 font-metric text-2xl tabular-nums text-hcl-navy">{value}</p>
      {sub ? <p className="text-xs text-hcl-muted">{sub}</p> : null}
      {children ? <div className="mt-2">{children}</div> : null}
    </div>
  );
}


interface BreakdownTileProps {
  title: string;
  rows: { label: string; calls: number; cost_usd: number }[];
}

function BreakdownTile({ title, rows }: BreakdownTileProps) {
  return (
    <div className="rounded-lg border border-border-subtle bg-surface p-4">
      <h3 className="mb-3 text-sm font-semibold text-hcl-navy">{title}</h3>
      {rows.length === 0 ? (
        <p className="text-sm text-hcl-muted">No data yet.</p>
      ) : (
        <ul className="space-y-1 text-sm text-hcl-navy">
          {rows.slice(0, 5).map((r) => (
            <li key={r.label} className="flex items-center justify-between">
              <span>{r.label}</span>
              <span className="font-metric tabular-nums text-hcl-muted">
                {r.calls} calls · {formatUsd(r.cost_usd)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
