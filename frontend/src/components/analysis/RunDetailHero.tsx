'use client';

import {
  AlertOctagon,
  CheckCircle2,
  Clock,
  Database,
  FileText,
  Flame,
  Github,
  KeyRound,
  Layers,
  Package,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  XCircle,
  type LucideIcon,
} from 'lucide-react';
import Link from 'next/link';
import { useMemo } from 'react';
import { Surface } from '@/components/ui/Surface';
import { AnimatedSeverityBar } from '@/components/ui/AnimatedSeverityBar';
import { cn, formatDate, formatDuration } from '@/lib/utils';
import type { AnalysisRun, EnrichedFinding } from '@/types';

type RunStatus = AnalysisRun['run_status'];

const STATUS_META: Record<
  RunStatus,
  { label: string; tone: string; chip: string; Icon: LucideIcon; ambient: string }
> = {
  PASS: {
    label: 'Passed',
    tone: 'text-emerald-700 dark:text-emerald-300',
    chip: 'bg-emerald-100 text-emerald-800 ring-emerald-300/60 dark:bg-emerald-950/60 dark:text-emerald-200 dark:ring-emerald-900/60',
    Icon: CheckCircle2,
    ambient: 'bg-emerald-300/30 dark:bg-emerald-700/20',
  },
  FAIL: {
    label: 'Findings detected',
    tone: 'text-red-700 dark:text-red-300',
    chip: 'bg-red-100 text-red-800 ring-red-300/60 dark:bg-red-950/60 dark:text-red-200 dark:ring-red-900/60',
    Icon: XCircle,
    ambient: 'bg-red-300/30 dark:bg-red-700/20',
  },
  PARTIAL: {
    label: 'Partial',
    tone: 'text-amber-700 dark:text-amber-300',
    chip: 'bg-amber-100 text-amber-800 ring-amber-300/60 dark:bg-amber-950/60 dark:text-amber-200 dark:ring-amber-900/60',
    Icon: AlertOctagon,
    ambient: 'bg-amber-300/30 dark:bg-amber-700/20',
  },
  ERROR: {
    label: 'Errored',
    tone: 'text-red-700 dark:text-red-300',
    chip: 'bg-red-100 text-red-800 ring-red-300/60 dark:bg-red-950/60 dark:text-red-200 dark:ring-red-900/60',
    Icon: XCircle,
    ambient: 'bg-red-300/30 dark:bg-red-700/20',
  },
  RUNNING: {
    label: 'Running',
    tone: 'text-sky-700 dark:text-sky-300',
    chip: 'bg-sky-100 text-sky-800 ring-sky-300/60 dark:bg-sky-950/60 dark:text-sky-200 dark:ring-sky-900/60',
    Icon: ScanSearch,
    ambient: 'bg-sky-300/30 dark:bg-sky-700/20',
  },
  PENDING: {
    label: 'Pending',
    tone: 'text-hcl-muted',
    chip: 'bg-surface-muted text-hcl-muted ring-border-subtle',
    Icon: Clock,
    ambient: 'bg-hcl-blue/20',
  },
  NO_DATA: {
    label: 'No data',
    tone: 'text-hcl-muted',
    chip: 'bg-surface-muted text-hcl-muted ring-border-subtle',
    Icon: ShieldCheck,
    ambient: 'bg-hcl-blue/20',
  },
};

const SOURCE_META: Record<string, { label: string; Icon: LucideIcon; tone: string; ring: string }> = {
  NVD: {
    label: 'NVD',
    Icon: ShieldAlert,
    tone: 'text-indigo-600 dark:text-indigo-400',
    ring: 'ring-indigo-200/60 dark:ring-indigo-900/60',
  },
  OSV: {
    label: 'OSV',
    Icon: Database,
    tone: 'text-emerald-600 dark:text-emerald-400',
    ring: 'ring-emerald-200/60 dark:ring-emerald-900/60',
  },
  GITHUB: {
    label: 'GHSA',
    Icon: Github,
    tone: 'text-purple-600 dark:text-purple-400',
    ring: 'ring-purple-200/60 dark:ring-purple-900/60',
  },
  GHSA: {
    label: 'GHSA',
    Icon: Github,
    tone: 'text-purple-600 dark:text-purple-400',
    ring: 'ring-purple-200/60 dark:ring-purple-900/60',
  },
  VULNDB: {
    label: 'VulDB',
    Icon: KeyRound,
    tone: 'text-cyan-700 dark:text-cyan-400',
    ring: 'ring-cyan-200/60 dark:ring-cyan-900/60',
  },
};

interface RunDetailHeroProps {
  run: AnalysisRun;
  /** Enriched findings — used to derive KEV count and worst risk score. */
  findings: EnrichedFinding[] | undefined;
  /** Slot for export controls and other actions. */
  rightSlot?: React.ReactNode;
}

function deriveBand(findings: EnrichedFinding[] | undefined): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'CLEAR' {
  if (!findings || findings.length === 0) return 'CLEAR';
  let worst = 0;
  let hasKevCritical = false;
  for (const f of findings) {
    if (f.risk_score > worst) worst = f.risk_score;
    if (f.in_kev && (f.score ?? 0) >= 9) hasKevCritical = true;
  }
  if (hasKevCritical || worst >= 80) return 'CRITICAL';
  if (worst >= 50) return 'HIGH';
  if (worst >= 20) return 'MEDIUM';
  if (worst > 0) return 'LOW';
  return 'CLEAR';
}

const BAND_CHIP: Record<ReturnType<typeof deriveBand>, string> = {
  CRITICAL: 'bg-red-100 text-red-800 ring-red-300/60 dark:bg-red-950/60 dark:text-red-200 dark:ring-red-900/60',
  HIGH: 'bg-orange-100 text-orange-800 ring-orange-300/60 dark:bg-orange-950/60 dark:text-orange-200 dark:ring-orange-900/60',
  MEDIUM: 'bg-amber-100 text-amber-800 ring-amber-300/60 dark:bg-amber-950/60 dark:text-amber-200 dark:ring-amber-900/60',
  LOW: 'bg-sky-100 text-sky-800 ring-sky-300/60 dark:bg-sky-950/60 dark:text-sky-200 dark:ring-sky-900/60',
  CLEAR: 'bg-emerald-100 text-emerald-800 ring-emerald-300/60 dark:bg-emerald-950/60 dark:text-emerald-200 dark:ring-emerald-900/60',
};

export function RunDetailHero({ run, findings, rightSlot }: RunDetailHeroProps) {
  const status = STATUS_META[run.run_status] ?? STATUS_META.NO_DATA;

  const sources = useMemo(() => {
    const parts = (run.source ?? '')
      .split(',')
      .map((s) => s.trim().toUpperCase())
      // strip trailing "(partial)" annotation
      .map((s) => s.replace(/\s*\(.*\)\s*$/, ''))
      .filter(Boolean);
    return Array.from(new Set(parts));
  }, [run.source]);

  const kevCount = useMemo(() => (findings ?? []).filter((f) => f.in_kev).length, [findings]);
  const worstRisk = useMemo(() => {
    if (!findings || findings.length === 0) return 0;
    return Math.max(...findings.map((f) => f.risk_score));
  }, [findings]);
  const band = deriveBand(findings);

  const counts = {
    critical: run.critical_count ?? 0,
    high: run.high_count ?? 0,
    medium: run.medium_count ?? 0,
    low: run.low_count ?? 0,
    unknown: run.unknown_count ?? 0,
  };

  return (
    <Surface
      variant="gradient"
      elevation={3}
      className="relative overflow-hidden p-6 motion-glide"
    >
      {/* Ambient glow tinted by run outcome */}
      <div
        aria-hidden
        className={cn(
          'pointer-events-none absolute -right-24 -top-24 h-64 w-64 rounded-full blur-3xl opacity-50',
          status.ambient,
        )}
      />

      <div className="relative flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
        {/* Left: title + chips + meta grid */}
        <div className="min-w-0 flex-1 space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <span className={cn('inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-semibold ring-1', status.chip)}>
              <status.Icon className="h-3.5 w-3.5" aria-hidden />
              {status.label}
            </span>
            <span className={cn('inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-semibold ring-1', BAND_CHIP[band])}>
              {band === 'CLEAR' ? (
                <ShieldCheck className="h-3.5 w-3.5" aria-hidden />
              ) : (
                <AlertOctagon className="h-3.5 w-3.5" aria-hidden />
              )}
              {band === 'CLEAR' ? 'All clear' : `${band} risk`}
            </span>
            {kevCount > 0 && (
              <span className="inline-flex items-center gap-1.5 rounded-full bg-red-50 px-3 py-1 text-xs font-semibold text-red-700 ring-1 ring-red-300/60 shadow-glow-critical dark:bg-red-950/60 dark:text-red-200 dark:ring-red-900/60">
                <Flame className="h-3.5 w-3.5" aria-hidden />
                {kevCount.toLocaleString()} KEV
              </span>
            )}
          </div>

          <div>
            <h2 className="text-display-lg font-semibold tracking-display text-hcl-navy">
              Run #{run.id}
              {run.sbom_name && (
                <span className="ml-2 text-base font-normal text-hcl-muted">
                  · {run.sbom_name}
                </span>
              )}
            </h2>
            <p className="font-metric mt-1 text-xs tabular-nums text-hcl-muted">
              {formatDate(run.started_on)}
              {run.completed_on && run.completed_on !== run.started_on && (
                <> → {formatDate(run.completed_on)}</>
              )}
              {run.duration_ms != null && (
                <> · <span className="text-hcl-navy">{formatDuration(run.duration_ms)}</span> elapsed</>
              )}
            </p>
          </div>

          {/* Meta tiles */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <MetaTile
              Icon={Package}
              label="Components"
              value={run.total_components?.toLocaleString() ?? '—'}
              hint={
                run.components_with_cpe != null
                  ? `${run.components_with_cpe.toLocaleString()} with CPE`
                  : undefined
              }
            />
            <MetaTile
              Icon={ShieldAlert}
              label="Findings"
              value={run.total_findings?.toLocaleString() ?? '0'}
              hint={
                worstRisk > 0
                  ? `Worst risk score ${worstRisk.toFixed(1)}`
                  : undefined
              }
              tone={(run.total_findings ?? 0) > 0 ? 'warn' : 'pass'}
            />
            <MetaTile
              Icon={Layers}
              label="Sources"
              value={sources.length.toString()}
              hint={sources.join(' · ') || '—'}
            />
            <MetaTile
              Icon={FileText}
              label="SBOM"
              value={
                run.sbom_id != null ? (
                  <Link
                    href={`/sboms/${run.sbom_id}`}
                    className="text-hcl-blue hover:underline"
                  >
                    #{run.sbom_id}
                  </Link>
                ) : (
                  '—'
                )
              }
              hint={run.sbom_name ?? '—'}
            />
          </div>
        </div>

        {/* Right: source chips + actions */}
        <div className="flex shrink-0 flex-col items-stretch gap-3 lg:items-end lg:min-w-[220px]">
          {sources.length > 0 && (
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wider text-hcl-muted lg:text-right">
                Sources queried
              </p>
              <ul className="mt-2 flex flex-wrap gap-1.5 lg:justify-end">
                {sources.map((s) => {
                  const meta = SOURCE_META[s] ?? {
                    label: s,
                    Icon: Database,
                    tone: 'text-hcl-muted',
                    ring: 'ring-border-subtle',
                  };
                  return (
                    <li key={s}>
                      <span
                        className={cn(
                          'inline-flex items-center gap-1.5 rounded-full bg-surface px-2.5 py-1 text-[11px] font-semibold ring-1',
                          meta.ring,
                        )}
                      >
                        <meta.Icon className={cn('h-3 w-3', meta.tone)} aria-hidden />
                        <span className="text-hcl-navy">{meta.label}</span>
                      </span>
                    </li>
                  );
                })}
              </ul>
            </div>
          )}

          {run.query_error_count != null && run.query_error_count > 0 && (
            <p className="font-metric text-[11px] tabular-nums text-amber-700 dark:text-amber-300 lg:text-right">
              {run.query_error_count} source query error{run.query_error_count === 1 ? '' : 's'}
            </p>
          )}

          {rightSlot && <div className="lg:ml-auto">{rightSlot}</div>}
        </div>
      </div>

      {/* Severity distribution */}
      <div className="relative mt-5 space-y-2">
        <p className="text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
          Severity distribution
        </p>
        <AnimatedSeverityBar counts={counts} triggerKey={run.id} />
        <ul className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-hcl-muted">
          {[
            { label: 'Critical', value: counts.critical, color: '#C0392B' },
            { label: 'High', value: counts.high, color: '#D4680A' },
            { label: 'Medium', value: counts.medium, color: '#B8860B' },
            { label: 'Low', value: counts.low, color: '#0067B1' },
            { label: 'Unknown', value: counts.unknown, color: '#6B7A8D' },
          ].map((s) => (
            <li key={s.label} className="inline-flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full" style={{ backgroundColor: s.color }} aria-hidden />
              <span>
                {s.label}: <strong className="text-hcl-navy">{s.value.toLocaleString()}</strong>
              </span>
            </li>
          ))}
        </ul>
      </div>
    </Surface>
  );
}

interface MetaTileProps {
  Icon: LucideIcon;
  label: string;
  value: React.ReactNode;
  hint?: string;
  tone?: 'pass' | 'warn' | 'idle';
}

function MetaTile({ Icon, label, value, hint, tone = 'idle' }: MetaTileProps) {
  return (
    <div className="rounded-lg border border-border-subtle bg-surface/70 px-3 py-2.5 backdrop-blur-sm">
      <div className="flex items-center gap-1.5">
        <Icon
          className={cn(
            'h-3.5 w-3.5',
            tone === 'pass' && 'text-emerald-600 dark:text-emerald-400',
            tone === 'warn' && 'text-amber-600 dark:text-amber-400',
            tone === 'idle' && 'text-hcl-muted',
          )}
          aria-hidden
        />
        <span className="text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
          {label}
        </span>
      </div>
      <p className="font-metric mt-1 text-xl font-bold tabular-nums text-hcl-navy">{value}</p>
      {hint && <p className="mt-0.5 truncate text-[11px] text-hcl-muted">{hint}</p>}
    </div>
  );
}
