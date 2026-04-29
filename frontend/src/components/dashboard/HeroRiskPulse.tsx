'use client';

import Link from 'next/link';
import { useMemo } from 'react';
import {
  ArrowDownRight,
  ArrowUpRight,
  Minus,
  Radar,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  Wrench,
} from 'lucide-react';
import { Surface } from '@/components/ui/Surface';
import { Skeleton } from '@/components/ui/Spinner';
import { Sparkline } from '@/components/ui/Sparkline';
import { cn } from '@/lib/utils';
import { pluralize } from '@/lib/pluralize';
import {
  POSTURE_COPY,
  derivePosture,
  exploitableCount,
  totalSeverity,
  type DashboardHealthInput,
  type PostureBand,
} from '@/lib/dashboardPosture';
import type {
  DashboardPosture,
  DashboardStats,
  DashboardTrend,
  HealthResponse,
} from '@/types';

type HealthShape = HealthResponse | undefined;

interface HeroRiskPulseProps {
  stats: DashboardStats | undefined;
  posture: DashboardPosture | undefined;
  trend: DashboardTrend | undefined;
  health: HealthShape;
  isLoading: boolean;
  /** Show a subtle live "syncing" pulse near the title. */
  isSyncing?: boolean;
}

const bandToTone: Record<
  PostureBand,
  { ring: string; chip: string; ambient: string; pillDot: string; pillTone: string }
> = {
  clean: {
    ring: 'ring-emerald-400/40',
    chip: 'bg-emerald-100 text-emerald-800 ring-emerald-300/60 dark:bg-emerald-950/60 dark:text-emerald-200 dark:ring-emerald-900/60',
    ambient: 'bg-emerald-300/30',
    pillDot: 'bg-emerald-500',
    pillTone: 'text-emerald-700 dark:text-emerald-300',
  },
  stable: {
    ring: 'ring-sky-400/40',
    chip: 'bg-sky-100 text-sky-800 ring-sky-300/60 dark:bg-sky-950/60 dark:text-sky-200 dark:ring-sky-900/60',
    ambient: 'bg-sky-300/30',
    pillDot: 'bg-sky-500',
    pillTone: 'text-sky-700 dark:text-sky-300',
  },
  action_needed: {
    ring: 'ring-orange-400/40',
    chip: 'bg-orange-100 text-orange-800 ring-orange-300/60 dark:bg-orange-950/60 dark:text-orange-200 dark:ring-orange-900/60',
    ambient: 'bg-orange-400/30',
    pillDot: 'bg-orange-500',
    pillTone: 'text-orange-700 dark:text-orange-300',
  },
  urgent: {
    ring: 'ring-red-400/40',
    chip: 'bg-red-100 text-red-800 ring-red-300/60 dark:bg-red-950/60 dark:text-red-200 dark:ring-red-900/60',
    ambient: 'bg-red-400/30',
    pillDot: 'bg-red-500',
    pillTone: 'text-red-700 dark:text-red-300',
  },
  degraded: {
    ring: 'ring-amber-400/40',
    chip: 'bg-amber-100 text-amber-800 ring-amber-300/60 dark:bg-amber-950/60 dark:text-amber-200 dark:ring-amber-900/60',
    ambient: 'bg-amber-300/30',
    pillDot: 'bg-amber-500',
    pillTone: 'text-amber-700 dark:text-amber-300',
  },
  empty: {
    ring: 'ring-slate-400/40',
    chip: 'bg-slate-100 text-slate-700 ring-slate-300/60 dark:bg-slate-900/60 dark:text-slate-300 dark:ring-slate-700/60',
    ambient: 'bg-slate-300/30',
    pillDot: 'bg-slate-500',
    pillTone: 'text-slate-600 dark:text-slate-400',
  },
};

function healthInputFrom(health: HealthShape): DashboardHealthInput {
  if (!health) return { apiOk: false };
  return { apiOk: health.status === 'ok' };
}

/**
 * Compute the percentage delta between the latest half of the trend window
 * and the previous half. Returns null when there isn't enough data to compare.
 *
 * The trend is plotted as a *raw finding count* (not a weighted score) — the
 * "weighted" label was removed in ADR-0001 because two different weight
 * vectors had drifted across this component.
 */
function computeDelta(
  trend: DashboardTrend | undefined,
): { pct: number; direction: 'up' | 'down' | 'flat' } | null {
  const series = trend?.series ?? [];
  if (series.length < 4) return null;
  const half = Math.floor(series.length / 2);
  const sumPoint = (p: { critical: number; high: number; medium: number; low: number }) =>
    p.critical + p.high + p.medium + p.low;
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
  posture,
  trend,
  health,
  isLoading,
  isSyncing = false,
}: HeroRiskPulseProps) {
  const result = useMemo(
    () => derivePosture({ posture, health: healthInputFrom(health) }),
    [posture, health],
  );
  const tone = bandToTone[result.band];
  const copy = POSTURE_COPY[result.band];

  const severity = posture?.severity;
  const totalFindings = stats?.total_findings ?? stats?.total_vulnerabilities ?? 0;
  const distinctVulns = stats?.total_distinct_vulnerabilities ?? totalFindings;
  const totalProjects = posture?.total_active_projects ?? stats?.total_active_projects ?? 0;
  const totalSboms = posture?.total_sboms ?? stats?.total_sboms ?? 0;
  const exploitable = exploitableCount(severity);
  const totalSev = totalSeverity(severity);
  const unknownCount = severity?.unknown ?? 0;
  const kevCount = posture?.kev_count ?? 0;
  const fixCount = posture?.fix_available_count ?? 0;

  // Severity bar — Critical/High/Medium/Low only. Unknown is a data-quality
  // signal (see docs/terminology.md) and is rendered as a separate pill.
  const segments = useMemo(() => {
    if (!severity || totalSev === 0) return [];
    return [
      { key: 'critical', value: severity.critical, color: '#C0392B', label: 'Critical' },
      { key: 'high', value: severity.high, color: '#D4680A', label: 'High' },
      { key: 'medium', value: severity.medium, color: '#B8860B', label: 'Medium' },
      { key: 'low', value: severity.low, color: '#0067B1', label: 'Low' },
    ].filter((s) => s.value > 0);
  }, [severity, totalSev]);

  const trendSeries = useMemo(
    () => (trend?.series ?? []).map((p) => p.critical + p.high + p.medium + p.low),
    [trend],
  );

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

  // Pluralized scope phrase, e.g. "1 SBOM in 1 active project".
  const scopePhrase = `${pluralize(totalSboms, 'SBOM', 'SBOMs')} in ${pluralize(totalProjects, 'active project', 'active projects')}`;

  // Subtext — adapts to the band, names the actionable count, and never
  // overstates what the data means.
  const subtext: React.ReactNode = (() => {
    if (result.band === 'empty') {
      return 'Upload an SBOM to see your security posture.';
    }
    if (result.band === 'degraded') {
      return (
        <>
          {result.reason}. The numbers below may be stale or incomplete.
        </>
      );
    }
    if (result.band === 'clean') {
      return <>No findings across {scopePhrase}.</>;
    }
    // urgent / action_needed / stable — name the actionable count.
    const exploitableSentence =
      exploitable > 0 ? (
        <>
          {' '}
          <span className="font-medium text-hcl-navy">{exploitable.toLocaleString()}</span>{' '}
          {pluralize(exploitable, 'exploitable finding', 'exploitable findings').replace(
            /^\d[\d,]*\s/,
            '',
          )}{' '}
          (Critical + High).
        </>
      ) : null;
    return (
      <>
        Aggregated across <strong className="font-semibold text-hcl-navy">{scopePhrase}</strong>{' '}
        — <span className="font-metric tabular-nums">{distinctVulns.toLocaleString()}</span>{' '}
        distinct {pluralize(distinctVulns, 'vulnerability', 'vulnerabilities').replace(
          /^\d[\d,]*\s/,
          '',
        )}
        .{exploitableSentence}
      </>
    );
  })();

  // LIVE pill text reflects the posture/health state — not just react-query
  // syncing state. ADR-0001 fixed the always-green-pulsing pill that
  // contradicted the Degraded footer.
  const livePillText = (() => {
    if (result.isDegraded) return 'Posture degraded';
    if (isSyncing) return 'Syncing security posture';
    if (result.band === 'empty') return 'No data yet';
    return 'Security posture · live';
  })();

  return (
    <Surface
      variant="gradient"
      elevation={3}
      className="motion-glide relative overflow-hidden p-6"
    >
      {/* Decorative ambient glow keyed off the posture band. */}
      <div
        aria-hidden="true"
        className={cn(
          'pointer-events-none absolute -right-24 -top-24 h-72 w-72 rounded-full blur-3xl opacity-40',
          tone.ambient,
        )}
      />

      <div className="relative flex flex-col gap-6 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0 flex-1 space-y-3">
          <div className="flex items-center gap-2">
            <span
              className={cn(
                'inline-flex h-2.5 w-2.5 rounded-full pulse-dot',
                tone.pillDot,
                !isSyncing && !result.isDegraded && 'opacity-70',
              )}
              aria-hidden="true"
            />
            <p className={cn('text-xs font-semibold uppercase tracking-wider', tone.pillTone)}>
              {livePillText}
            </p>
          </div>

          {/* Headline — aria-live so screen readers announce posture changes. */}
          <div className="flex items-baseline gap-3" aria-live="polite">
            <h2 className="text-display-lg font-semibold tracking-display text-hcl-navy">
              {copy.headline}
            </h2>
            <span
              className={cn(
                'inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-semibold ring-1',
                tone.chip,
              )}
              title={result.reason}
            >
              {result.band === 'clean' ? (
                <ShieldCheck className="h-3.5 w-3.5" aria-hidden />
              ) : result.band === 'degraded' ? (
                <ShieldQuestion className="h-3.5 w-3.5" aria-hidden />
              ) : result.band === 'urgent' ? (
                <ShieldAlert className="h-3.5 w-3.5" aria-hidden />
              ) : (
                <Radar className="h-3.5 w-3.5" aria-hidden />
              )}
              {pluralize(totalFindings, 'finding', 'findings')}
            </span>
          </div>

          <p className="max-w-2xl text-sm leading-relaxed text-hcl-muted">{subtext}</p>

          {/* Severity bar — proportional segments. Unknown rendered separately below. */}
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
              <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-hcl-muted">
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
                {unknownCount > 0 && (
                  <span
                    className="inline-flex items-center gap-1.5 rounded-full bg-slate-100 px-2 py-0.5 text-[11px] text-slate-600 ring-1 ring-slate-200 dark:bg-slate-900/60 dark:text-slate-300 dark:ring-slate-700/60"
                    title="Unknown is a data-quality signal — these findings have no CVSS score in our feeds. Not counted in severity totals."
                  >
                    <span className="h-1.5 w-1.5 rounded-full bg-slate-400" aria-hidden />
                    {unknownCount.toLocaleString()} with unscored severity
                  </span>
                )}
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

        {/* Right column — KEV / fix-available tiles + trend + CTA.
            Risk Index removed in ADR-0001; replaced with KEV + fix-available. */}
        <div className="flex shrink-0 items-stretch gap-5 lg:flex-col lg:items-end lg:gap-3">
          <div className="grid grid-cols-2 gap-3">
            <PostureMetricTile
              icon={<ShieldAlert className="h-3.5 w-3.5" aria-hidden />}
              label="On CISA KEV"
              value={kevCount}
              tone={kevCount > 0 ? 'red' : 'neutral'}
              tooltip="Distinct vulnerabilities (in scope of the latest successful run per SBOM) that appear on the CISA Known Exploited Vulnerabilities catalog. Source: cisa.gov/known-exploited-vulnerabilities-catalog."
            />
            <PostureMetricTile
              icon={<Wrench className="h-3.5 w-3.5" aria-hidden />}
              label="Fix available"
              value={fixCount}
              tone={fixCount > 0 ? 'sky' : 'neutral'}
              tooltip="Distinct vulnerabilities (same scope) whose upstream advisory provides at least one fixed version. Operationally actionable subset."
            />
          </div>

          <div className="flex flex-col items-end gap-1.5">
            <Sparkline
              data={trendSeries}
              width={160}
              height={44}
              color="var(--color-hcl-blue)"
              ariaLabel={
                trend?.days
                  ? `Finding count over the last ${trend.days} days`
                  : 'Finding count trend'
              }
            />
            <span className="text-[10px] uppercase tracking-wider text-hcl-muted">
              {trend?.days ? `${trend.days}-day finding trend` : 'Finding trend'}
            </span>
            {delta && (
              <span
                className={cn(
                  'inline-flex items-center gap-1 text-xs font-semibold',
                  delta.direction === 'up' && 'text-red-600 dark:text-red-400',
                  delta.direction === 'down' && 'text-emerald-600 dark:text-emerald-400',
                  delta.direction === 'flat' && 'text-hcl-muted',
                )}
              >
                {delta.direction === 'up' && <ArrowUpRight className="h-3.5 w-3.5" aria-hidden />}
                {delta.direction === 'down' && (
                  <ArrowDownRight className="h-3.5 w-3.5" aria-hidden />
                )}
                {delta.direction === 'flat' && <Minus className="h-3.5 w-3.5" aria-hidden />}
                {delta.direction === 'flat'
                  ? 'No change'
                  : `${Math.abs(delta.pct).toFixed(0)}% vs prior period`}
              </span>
            )}
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

interface PostureMetricTileProps {
  icon: React.ReactNode;
  label: string;
  value: number;
  tone: 'red' | 'sky' | 'neutral';
  tooltip: string;
}

function PostureMetricTile({ icon, label, value, tone, tooltip }: PostureMetricTileProps) {
  const toneClasses =
    tone === 'red'
      ? 'border-red-200 bg-red-50/60 text-red-700 dark:border-red-900 dark:bg-red-950/30 dark:text-red-300'
      : tone === 'sky'
        ? 'border-sky-200 bg-sky-50/60 text-sky-700 dark:border-sky-900 dark:bg-sky-950/30 dark:text-sky-300'
        : 'border-border bg-surface/60 text-hcl-muted';
  return (
    <div
      className={cn(
        'rounded-lg border px-3 py-2 transition-colors duration-base',
        toneClasses,
      )}
      title={tooltip}
    >
      <div className="flex items-center gap-1.5 text-[10px] font-medium uppercase tracking-wider">
        {icon}
        {label}
      </div>
      <div className="mt-0.5 font-metric text-xl font-bold leading-tight tabular-nums">
        {value.toLocaleString()}
      </div>
    </div>
  );
}
