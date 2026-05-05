'use client';

import { ArrowRight } from 'lucide-react';
import { useAiSettings } from '@/hooks/useAiFix';

interface UsageSummaryProps {
  /** Optional href for the "View detail" link — defaults to the cost dashboard. */
  detailHref?: string;
}

/**
 * Phase 3 §3.7 — lightweight inline summary.
 *
 * Defers to the existing cost dashboard (``/admin/ai-usage``) for the
 * full breakdown — this tile only shows the headline numbers.
 */
export function UsageSummary({ detailHref = '/admin/ai-usage' }: UsageSummaryProps) {
  const { usage } = useAiSettings();

  return (
    <section
      className="rounded-lg border border-border-subtle bg-surface p-4"
      aria-labelledby="ai-usage-summary-heading"
    >
      <header className="flex items-center justify-between">
        <h2 id="ai-usage-summary-heading" className="text-base font-semibold text-hcl-navy">
          Usage this month
        </h2>
        <a
          href={detailHref}
          className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
        >
          View detail <ArrowRight className="h-3 w-3" aria-hidden />
        </a>
      </header>

      <dl className="mt-3 grid grid-cols-3 gap-3 text-sm">
        <Tile label="Total spent" value={formatUsd(usage?.last_30_days.total_cost_usd)} />
        <Tile
          label="Cache hit rate"
          value={
            usage
              ? `${(usage.last_30_days.cache_hit_ratio * 100).toFixed(1)}%`
              : '—'
          }
        />
        <Tile
          label="Most-used"
          value={
            usage && usage.by_provider.length > 0
              ? `${usage.by_provider[0].label} (${formatRatio(
                  usage.by_provider[0],
                  usage.last_30_days.total_calls,
                )})`
              : '—'
          }
        />
      </dl>
    </section>
  );
}


interface TileProps {
  label: string;
  value: string;
}


function Tile({ label, value }: TileProps) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wide text-hcl-muted">{label}</dt>
      <dd className="mt-1 font-metric tabular-nums text-base text-hcl-navy">{value}</dd>
    </div>
  );
}


function formatUsd(usd: number | null | undefined): string {
  if (usd == null) return '—';
  if (usd === 0) return '$0.00';
  if (usd < 0.01) return '<$0.01';
  return `$${usd.toFixed(2)}`;
}


function formatRatio(b: { calls: number }, total: number): string {
  if (total <= 0) return '—';
  return `${Math.round((b.calls / total) * 100)}%`;
}
