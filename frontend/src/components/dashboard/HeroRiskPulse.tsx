'use client';

import Link from 'next/link';
import { useMemo } from 'react';
import { ArrowDownRight, ArrowUpRight, Minus, Radar, ShieldCheck } from 'lucide-react';
import { Surface } from '@/components/ui/Surface';
import { Skeleton } from '@/components/ui/Spinner';
import { Sparkline } from '@/components/ui/Sparkline';
import { cn } from '@/lib/utils';
import type { DashboardStats, DashboardTrend, SeverityData } from '@/types';

interface HeroRiskPulseProps {
  stats: DashboardStats | undefined;
  severity: SeverityData | undefined;
  trend: DashboardTrend | undefined;
  isLoading: boolean;
  /** Show a subtle live "syncing" pulse near the title. */
  isSyncing?: boolean;
}

type RiskBand = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'CLEAR';

const riskBandStyles: Record<
  RiskBand,
  { label: string; tone: string; bar: string; chip: string; ring: string; glow: string }
> = {
  CRITICAL: {
    label: 'Critical',
    tone: 'text-red-700 dark:text-red-300',
    bar: 'from-red-600 via-red-500 to-orange-500',
    chip: 'bg-red-100 text-red-800 ring-red-300/60 dark:bg-red-950/60 dark:text-red-200 dark:ring-red-900/60',
    ring: 'ring-red-400/40',
    glow: 'glow-critical',
  },
  HIGH: {
    label: 'High',
    tone: 'text-orange-700 dark:text-orange-300',
    bar: 'from-orange-500 via-amber-500 to-yellow-400',
    chip: 'bg-orange-100 text-orange-800 ring-orange-300/60 dark:bg-orange-950/60 dark:text-orange-200 dark:ring-orange-900/60',
    ring: 'ring-orange-400/40',
    glow: '',
  },
  MEDIUM: {
    label: 'Medium',
    tone: 'text-amber-700 dark:text-amber-300',
    bar: 'from-amber-500 via-yellow-400 to-yellow-300',
    chip: 'bg-amber-100 text-amber-800 ring-amber-300/60 dark:bg-amber-950/60 dark:text-amber-200 dark:ring-amber-900/60',
    ring: 'ring-amber-400/40',
    glow: '',
  },
  LOW: {
    label: 'Low',
    tone: 'text-sky-700 dark:text-sky-300',
    bar: 'from-sky-500 via-cyan-400 to-emerald-400',
    chip: 'bg-sky-100 text-sky-800 ring-sky-300/60 dark:bg-sky-950/60 dark:text-sky-200 dark:ring-sky-900/60',
    ring: 'ring-sky-400/40',
    glow: '',
  },
  CLEAR: {
    label: 'All clear',
    tone: 'text-emerald-700 dark:text-emerald-300',
    bar: 'from-emerald-500 via-emerald-400 to-cyan-400',
    chip: 'bg-emerald-100 text-emerald-800 ring-emerald-300/60 dark:bg-emerald-950/60 dark:text-emerald-200 dark:ring-emerald-900/60',
    ring: 'ring-emerald-400/40',
    glow: 'glow-success',
  },
};

function deriveBand(severity: SeverityData | undefined): RiskBand {
  if (!severity) return 'CLEAR';
  if (severity.critical > 0) return 'CRITICAL';
  if (severity.high > 0) return 'HIGH';
  if (severity.medium > 0) return 'MEDIUM';
  if (severity.low > 0 || severity.unknown > 0) return 'LOW';
  return 'CLEAR';
}

function severityWeight(s: SeverityData | undefined): number {
  if (!s) return 0;
  // Weighted urgency score that mirrors the band thresholds.
  return s.critical * 100 + s.high * 25 + s.medium * 8 + s.low * 2 + s.unknown;
}

/**
 * Compute the percentage delta between the latest half of the trend window
 * and the previous half. Returns null when there isn't enough data to compare.
 */
function computeDelta(trend: DashboardTrend | undefined): { pct: number; direction: 'up' | 'down' | 'flat' } | null {
  const series = trend?.series ?? [];
  if (series.length < 4) return null;
  const half = Math.floor(series.length / 2);
  const sumPoint = (p: { critical: number; high: number; medium: number; low: number }) =>
    p.critical * 100 + p.high * 25 + p.medium * 8 + p.low * 2;
  const earlier = series.slice(0, half).reduce((s, p) => s + sumPoint(p), 0);
  const later = series.slice(-half).reduce((s, p) => s + sumPoint(p), 0);
  if (earlier === 0 && later === 0) return { pct: 0, direction: 'flat' };
  if (earlier === 0) return { pct: 100, direction: 'up' };
  const pct = ((later - earlier) / earlier) * 100;
  if (Math.abs(pct) < 1) return { pct: 0, direction: 'flat' };
  return { pct, direction: pct > 0 ? 'up' : 'down' };
}

export function HeroRiskPulse({
  stats,
  severity,
  trend,
  isLoading,
  isSyncing = false,
}: HeroRiskPulseProps) {
  const band = deriveBand(severity);
  const styles = riskBandStyles[band];
  const totalFindings = stats?.total_vulnerabilities ?? 0;
  const totalProjects = stats?.total_projects ?? 0;
  const totalSboms = stats?.total_sboms ?? 0;

  const weighted = severityWeight(severity);
  const totalSev = severity
    ? severity.critical + severity.high + severity.medium + severity.low + severity.unknown
    : 0;

  // Severity bar segments — width proportional to weighted contribution
  const segments = useMemo(() => {
    if (!severity || totalSev === 0) return [];
    return [
      { key: 'critical', value: severity.critical, color: '#C0392B', label: 'Critical' },
      { key: 'high', value: severity.high, color: '#D4680A', label: 'High' },
      { key: 'medium', value: severity.medium, color: '#B8860B', label: 'Medium' },
      { key: 'low', value: severity.low, color: '#0067B1', label: 'Low' },
      { key: 'unknown', value: severity.unknown, color: '#6B7A8D', label: 'Unknown' },
    ].filter((s) => s.value > 0);
  }, [severity, totalSev]);

  const trendSeries = useMemo(() => {
    return (trend?.series ?? []).map((p) => p.critical * 4 + p.high + p.medium * 0.4 + p.low * 0.1);
  }, [trend]);

  const delta = computeDelta(trend);

  if (isLoading) {
    return (
      <Surface variant="gradient" elevation={3} className="overflow-hidden p-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="space-y-3">
            <Skeleton className="h-3 w-24" />
            <Skeleton className="h-8 w-72" />
            <Skeleton className="h-3 w-96" />
          </div>
          <div className="flex gap-6">
            <Skeleton className="h-20 w-20 rounded-full" />
            <Skeleton className="h-20 w-32" />
          </div>
        </div>
        <div className="mt-5 h-3 w-full overflow-hidden rounded-full">
          <Skeleton className="h-full w-full" />
        </div>
      </Surface>
    );
  }

  return (
    <Surface
      variant="gradient"
      elevation={3}
      className="motion-glide relative overflow-hidden p-6"
    >
      {/* Decorative ambient glow */}
      <div
        aria-hidden="true"
        className={cn(
          'pointer-events-none absolute -right-24 -top-24 h-72 w-72 rounded-full blur-3xl opacity-40',
          band === 'CRITICAL' && 'bg-red-400/30',
          band === 'HIGH' && 'bg-orange-400/30',
          band === 'MEDIUM' && 'bg-amber-300/30',
          band === 'LOW' && 'bg-sky-300/30',
          band === 'CLEAR' && 'bg-emerald-300/30',
        )}
      />

      <div className="relative flex flex-col gap-6 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0 flex-1 space-y-3">
          <div className="flex items-center gap-2">
            <span
              className={cn(
                'inline-flex h-2.5 w-2.5 rounded-full bg-emerald-500 pulse-dot text-emerald-500',
                !isSyncing && 'opacity-70',
              )}
              aria-hidden="true"
            />
            <p className="text-xs font-semibold uppercase tracking-wider text-hcl-muted">
              {isSyncing ? 'Syncing security posture' : 'Security posture · live'}
            </p>
          </div>

          <div className="flex items-baseline gap-3">
            <h2 className="text-display-lg font-semibold tracking-display text-hcl-navy">
              {band === 'CLEAR' ? 'All clear' : `${styles.label} risk`}
            </h2>
            <span
              className={cn(
                'inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-semibold ring-1',
                styles.chip,
              )}
            >
              {band === 'CLEAR' ? (
                <ShieldCheck className="h-3.5 w-3.5" aria-hidden />
              ) : (
                <Radar className="h-3.5 w-3.5" aria-hidden />
              )}
              {totalFindings.toLocaleString()} findings
            </span>
          </div>

          <p className="max-w-2xl text-sm leading-relaxed text-hcl-muted">
            {band === 'CLEAR' ? (
              <>No active vulnerabilities across {totalSboms.toLocaleString()} SBOMs in {totalProjects.toLocaleString()} projects.</>
            ) : (
              <>
                Aggregated across <strong className="font-semibold text-hcl-navy">{totalSboms.toLocaleString()}</strong> SBOMs in{' '}
                <strong className="font-semibold text-hcl-navy">{totalProjects.toLocaleString()}</strong> projects.
                {severity && severity.critical > 0 && (
                  <>
                    {' '}
                    <span className="font-medium text-red-700 dark:text-red-400">{severity.critical.toLocaleString()}</span> critical {severity.critical === 1 ? 'finding requires' : 'findings require'} attention.
                  </>
                )}
              </>
            )}
          </p>

          {/* Severity bar — proportional segments */}
          {segments.length > 0 ? (
            <div className="pt-2">
              <div
                role="img"
                aria-label={`Severity distribution: ${segments
                  .map((s) => `${s.label} ${s.value}`)
                  .join(', ')}`}
                className="flex h-2.5 w-full overflow-hidden rounded-full bg-border-subtle"
              >
                {segments.map((seg) => (
                  <div
                    key={seg.key}
                    className="h-full transition-all duration-slower ease-spring"
                    style={{
                      width: `${(seg.value / totalSev) * 100}%`,
                      backgroundColor: seg.color,
                    }}
                    title={`${seg.label}: ${seg.value.toLocaleString()}`}
                  />
                ))}
              </div>
              <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-hcl-muted">
                {segments.map((seg) => (
                  <span key={seg.key} className="inline-flex items-center gap-1.5">
                    <span
                      className="h-2 w-2 rounded-full"
                      style={{ backgroundColor: seg.color }}
                      aria-hidden
                    />
                    {seg.label}: <strong className="text-hcl-navy">{seg.value.toLocaleString()}</strong>
                  </span>
                ))}
              </div>
            </div>
          ) : (
            <div className="pt-2">
              <div className="flex h-2.5 w-full items-center justify-center rounded-full bg-emerald-100 dark:bg-emerald-950/60">
                <span className="text-[10px] font-medium uppercase tracking-wider text-emerald-700 dark:text-emerald-300">
                  No findings
                </span>
              </div>
            </div>
          )}
        </div>

        {/* Right: trend mini-chart + delta */}
        <div className="flex shrink-0 items-stretch gap-5 lg:flex-col lg:items-end lg:gap-3">
          <div className={cn('flex flex-col items-end justify-center', styles.tone)}>
            <span className="text-xs font-medium uppercase tracking-wider text-hcl-muted">
              Risk index
            </span>
            <span className="font-metric text-3xl font-bold leading-tight">
              {weighted.toLocaleString()}
            </span>
            {delta && (
              <span className={cn(
                'mt-0.5 inline-flex items-center gap-1 text-xs font-semibold',
                delta.direction === 'up' && 'text-red-600 dark:text-red-400',
                delta.direction === 'down' && 'text-emerald-600 dark:text-emerald-400',
                delta.direction === 'flat' && 'text-hcl-muted',
              )}>
                {delta.direction === 'up' && <ArrowUpRight className="h-3.5 w-3.5" aria-hidden />}
                {delta.direction === 'down' && <ArrowDownRight className="h-3.5 w-3.5" aria-hidden />}
                {delta.direction === 'flat' && <Minus className="h-3.5 w-3.5" aria-hidden />}
                {delta.direction === 'flat'
                  ? 'No change'
                  : `${Math.abs(delta.pct).toFixed(0)}% vs prior period`}
              </span>
            )}
          </div>

          <div className="flex flex-col items-end gap-1.5">
            <Sparkline
              data={trendSeries}
              width={160}
              height={44}
              color="var(--color-hcl-blue)"
              ariaLabel={
                trend?.days
                  ? `Weighted findings trend over the last ${trend.days} days`
                  : 'Findings trend'
              }
            />
            <span className="text-[10px] uppercase tracking-wider text-hcl-muted">
              {trend?.days ? `${trend.days}-day weighted trend` : 'Trend'}
            </span>
          </div>

          <Link
            href="/analysis?tab=runs"
            className="inline-flex items-center gap-1.5 self-end rounded-lg border border-border bg-surface/60 px-3 py-1.5 text-xs font-medium text-hcl-navy backdrop-blur-sm transition-all duration-base ease-spring hover:-translate-y-px hover:border-primary/50 hover:text-primary hover:shadow-glow-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40"
          >
            View runs
            <ArrowUpRight className="h-3.5 w-3.5" aria-hidden />
          </Link>
        </div>
      </div>
    </Surface>
  );
}
