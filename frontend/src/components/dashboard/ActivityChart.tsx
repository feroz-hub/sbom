'use client';

import { Activity, Archive, ArrowUpRight } from 'lucide-react';
import Link from 'next/link';
import { Surface, SurfaceContent, SurfaceHeader } from '@/components/ui/Surface';
import { Spinner } from '@/components/ui/Spinner';
import { EmptyState } from '@/components/ui/EmptyState';
import { cn } from '@/lib/utils';
import type { ActivityData } from '@/types';

interface ActivityChartProps {
  data: ActivityData | undefined;
  isLoading: boolean;
}

/**
 * SBOM activity panel — proportional ring + descriptive callout.
 *
 * Replaces the previous Recharts donut: the data has only two buckets
 * (active vs. stale) so a chart is overkill; an SVG ring with two segments
 * communicates the split more directly and renders without a chart library.
 */
export function ActivityChart({ data, isLoading }: ActivityChartProps) {
  const total = data ? data.active_30d + data.stale : 0;
  const activePct = total > 0 ? (data!.active_30d / total) * 100 : 0;
  const stalePct = 100 - activePct;
  const isHealthy = total === 0 ? null : activePct >= 60;

  return (
    <Surface variant="elevated">
      <SurfaceHeader>
        <div>
          <h3 className="text-base font-semibold text-hcl-navy">SBOM activity</h3>
          <p className="mt-0.5 text-xs text-hcl-muted">
            Updated within last 30 days vs older.
          </p>
        </div>
        {total > 0 && (
          <Link
            href="/sboms"
            className="inline-flex items-center gap-1 text-xs font-medium text-primary transition-colors hover:text-hcl-dark"
          >
            View all <ArrowUpRight className="h-3 w-3" aria-hidden />
          </Link>
        )}
      </SurfaceHeader>
      <SurfaceContent>
        {isLoading ? (
          <div className="flex h-56 items-center justify-center">
            <Spinner />
          </div>
        ) : total === 0 ? (
          <EmptyState
            illustration="no-sboms"
            title="No SBOMs uploaded"
            description="Upload an SBOM to start tracking activity."
            compact
          />
        ) : (
          <div className="grid grid-cols-1 items-center gap-6 sm:grid-cols-[auto_1fr]">
            <ProgressRing
              activePct={activePct}
              total={total}
            />
            <div className="space-y-3">
              <ActivityRow
                Icon={Activity}
                tone="text-emerald-600 dark:text-emerald-400"
                bg="bg-emerald-50 dark:bg-emerald-950/40"
                label="Active"
                hint="≤ 30 days"
                count={data!.active_30d}
                pct={activePct}
              />
              <ActivityRow
                Icon={Archive}
                tone="text-amber-600 dark:text-amber-400"
                bg="bg-amber-50 dark:bg-amber-950/40"
                label="Stale"
                hint="> 30 days old"
                count={data!.stale}
                pct={stalePct}
              />
              <p
                className={cn(
                  'rounded-lg border px-3 py-2 text-xs',
                  isHealthy
                    ? 'border-emerald-200 bg-emerald-50/50 text-emerald-800 dark:border-emerald-900/60 dark:bg-emerald-950/30 dark:text-emerald-300'
                    : 'border-amber-200 bg-amber-50/50 text-amber-800 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-300',
                )}
              >
                {isHealthy
                  ? 'Healthy refresh cadence — most SBOMs were updated recently.'
                  : 'Many SBOMs are stale — consider re-uploading or scheduling refreshes.'}
              </p>
            </div>
          </div>
        )}
      </SurfaceContent>
    </Surface>
  );
}

function ProgressRing({ activePct, total }: { activePct: number; total: number }) {
  const radius = 56;
  const circumference = 2 * Math.PI * radius;
  const activeStroke = (activePct / 100) * circumference;
  return (
    <div className="relative h-[140px] w-[140px] shrink-0">
      <svg
        viewBox="0 0 140 140"
        width="140"
        height="140"
        role="img"
        aria-label={`${activePct.toFixed(0)}% active SBOMs`}
        className="-rotate-90"
      >
        <defs>
          <linearGradient id="activity-active" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#0067B1" />
            <stop offset="100%" stopColor="#00B2E2" />
          </linearGradient>
        </defs>
        <circle
          cx="70"
          cy="70"
          r={radius}
          stroke="var(--color-border-subtle)"
          strokeWidth="14"
          fill="none"
        />
        <circle
          cx="70"
          cy="70"
          r={radius}
          stroke="url(#activity-active)"
          strokeWidth="14"
          strokeLinecap="round"
          fill="none"
          strokeDasharray={`${activeStroke} ${circumference}`}
          style={{
            transition: 'stroke-dasharray 700ms cubic-bezier(0.34, 1.56, 0.64, 1)',
          }}
        />
      </svg>
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center text-center">
        <span className="font-metric text-2xl font-bold leading-none text-hcl-navy">
          {activePct.toFixed(0)}%
        </span>
        <span className="mt-0.5 text-[10px] font-medium uppercase tracking-wider text-hcl-muted">
          Active
        </span>
        <span className="mt-1 font-metric text-[10px] tabular-nums text-hcl-muted">
          {total.toLocaleString()} total
        </span>
      </div>
    </div>
  );
}

interface ActivityRowProps {
  Icon: typeof Activity;
  tone: string;
  bg: string;
  label: string;
  hint: string;
  count: number;
  pct: number;
}

function ActivityRow({ Icon, tone, bg, label, hint, count, pct }: ActivityRowProps) {
  return (
    <div className="flex items-center gap-3">
      <div className={cn('flex h-9 w-9 shrink-0 items-center justify-center rounded-lg', bg)}>
        <Icon className={cn('h-4 w-4', tone)} aria-hidden />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-baseline justify-between gap-2">
          <span className="text-sm font-medium text-hcl-navy">{label}</span>
          <span className="font-metric text-sm font-semibold text-hcl-navy">
            {count.toLocaleString()}
            <span className="ml-1 text-[10px] tabular-nums text-hcl-muted">{pct.toFixed(0)}%</span>
          </span>
        </div>
        <span className="text-[11px] text-hcl-muted">{hint}</span>
      </div>
    </div>
  );
}
