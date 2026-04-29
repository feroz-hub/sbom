'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock,
  Database,
  Github,
  KeyRound,
  Loader2,
  PauseCircle,
  ShieldAlert,
  X,
  XCircle,
  type LucideIcon,
} from 'lucide-react';
import { Alert } from '@/components/ui/Alert';
import { Surface, SurfaceContent, SurfaceFooter, SurfaceHeader } from '@/components/ui/Surface';
import { Button } from '@/components/ui/Button';
import { AnimatedSeverityBar } from '@/components/ui/AnimatedSeverityBar';
import { cn, formatDuration } from '@/lib/utils';
import type {
  AnalysisStreamState,
  SourceProgress,
  SourceStatus,
} from '@/hooks/useAnalysisStream';

const SOURCE_META: Record<string, { label: string; Icon: LucideIcon; tone: string }> = {
  NVD: { label: 'NVD', Icon: ShieldAlert, tone: 'text-indigo-600 dark:text-indigo-400' },
  OSV: { label: 'OSV', Icon: Database, tone: 'text-emerald-600 dark:text-emerald-400' },
  GITHUB: { label: 'GHSA', Icon: Github, tone: 'text-purple-600 dark:text-purple-400' },
  GHSA: { label: 'GHSA', Icon: Github, tone: 'text-purple-600 dark:text-purple-400' },
  VULNDB: { label: 'VulDB', Icon: KeyRound, tone: 'text-cyan-700 dark:text-cyan-400' },
};

function statusTone(status: SourceStatus): {
  ring: string;
  bg: string;
  Icon: LucideIcon;
  iconClass: string;
  pulse: boolean;
  label: string;
} {
  switch (status) {
    case 'running':
      return {
        ring: 'ring-sky-300/60 dark:ring-sky-800/60',
        bg: 'bg-sky-50/60 dark:bg-sky-950/30',
        Icon: Loader2,
        iconClass: 'text-sky-600 animate-spin motion-reduce:animate-none',
        pulse: true,
        label: 'Querying',
      };
    case 'complete':
      return {
        ring: 'ring-emerald-300/60 dark:ring-emerald-900/60',
        bg: 'bg-emerald-50/60 dark:bg-emerald-950/30',
        Icon: CheckCircle2,
        iconClass: 'text-emerald-600 dark:text-emerald-400',
        pulse: false,
        label: 'Complete',
      };
    case 'error':
      return {
        ring: 'ring-red-300/60 dark:ring-red-900/60',
        bg: 'bg-red-50/60 dark:bg-red-950/30',
        Icon: XCircle,
        iconClass: 'text-red-600 dark:text-red-400',
        pulse: false,
        label: 'Failed',
      };
    case 'skipped':
      return {
        ring: 'ring-amber-300/60 dark:ring-amber-900/60',
        bg: 'bg-amber-50/60 dark:bg-amber-950/30',
        Icon: PauseCircle,
        iconClass: 'text-amber-600 dark:text-amber-400',
        pulse: false,
        label: 'Skipped',
      };
    default:
      return {
        ring: 'ring-border-subtle',
        bg: 'bg-surface-muted/50',
        Icon: Clock,
        iconClass: 'text-hcl-muted',
        pulse: false,
        label: 'Pending',
      };
  }
}

function formatElapsed(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const secs = Math.floor(ms / 1000);
  if (secs < 60) return `${secs}s`;
  const mins = Math.floor(secs / 60);
  return `${mins}m ${secs % 60}s`;
}

interface SourceLiveCardProps {
  source: SourceProgress;
}

function SourceLiveCard({ source }: SourceLiveCardProps) {
  const meta = SOURCE_META[source.name] ?? {
    label: source.name,
    Icon: Database,
    tone: 'text-hcl-muted',
  };
  const tone = statusTone(source.status);

  return (
    <li
      className={cn(
        'relative overflow-hidden rounded-lg ring-1 px-3 py-2.5 transition-all duration-base ease-spring motion-reduce:transition-none',
        tone.ring,
        tone.bg,
        source.status === 'running' && 'shadow-glow-cyan',
      )}
    >
      <div className="flex items-start gap-3">
        <span
          className={cn(
            'flex h-9 w-9 shrink-0 items-center justify-center rounded-md',
            tone.bg,
            'ring-1',
            tone.ring,
          )}
        >
          <meta.Icon className={cn('h-4 w-4', meta.tone)} aria-hidden />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-baseline justify-between gap-2">
            <p className="text-sm font-semibold text-hcl-navy">{meta.label}</p>
            <span className="font-metric text-[10px] tabular-nums text-hcl-muted">
              {source.sourceMs > 0
                ? formatDuration(source.sourceMs)
                : source.elapsedMs > 0
                  ? formatElapsed(source.elapsedMs)
                  : ''}
            </span>
          </div>
          <div className="mt-0.5 flex items-center gap-1.5">
            <tone.Icon
              className={cn('h-3.5 w-3.5', tone.iconClass)}
              aria-hidden
            />
            <span className="text-[11px] font-medium text-hcl-navy">
              {tone.label}
              {source.status === 'running' && '…'}
            </span>
          </div>
          {source.status === 'complete' && (
            <p className="font-metric mt-1 text-[11px] tabular-nums text-hcl-muted">
              <strong className="text-hcl-navy">{source.findings.toLocaleString()}</strong>{' '}
              finding{source.findings === 1 ? '' : 's'}
              {source.errors > 0 && (
                <>
                  {' · '}
                  <span className="text-amber-700 dark:text-amber-300">
                    {source.errors} error{source.errors === 1 ? '' : 's'}
                  </span>
                </>
              )}
            </p>
          )}
          {source.status === 'error' && source.error && (
            <p className="mt-1 line-clamp-2 text-[11px] text-red-700 dark:text-red-300">
              {source.error}
            </p>
          )}
        </div>
      </div>
    </li>
  );
}

interface LiveAnalysisCardProps {
  state: AnalysisStreamState;
  onCancel?: () => void;
  onReset?: () => void;
}

export function LiveAnalysisCard({ state, onCancel, onReset }: LiveAnalysisCardProps) {
  const router = useRouter();
  const { phase, components, sources, elapsedMs, runId, summary, error } = state;

  if (phase === 'idle') return null;

  const sourceList = Object.values(sources);
  const isRunning = phase === 'connecting' || phase === 'parsing' || phase === 'running';
  const isDone = phase === 'done';
  const isError = phase === 'error';

  const phaseLabel = (() => {
    if (phase === 'connecting') return 'Opening live stream';
    if (phase === 'parsing') return 'Parsing SBOM';
    if (phase === 'running') return 'Querying sources';
    if (phase === 'done') return 'Analysis complete';
    if (phase === 'error') return 'Analysis interrupted';
    return '';
  })();

  // Aggregate progress: % of sources that have finished (complete/error/skipped).
  const finishedSources = sourceList.filter((s) =>
    s.status === 'complete' || s.status === 'error' || s.status === 'skipped',
  ).length;
  const progressPct = sourceList.length > 0 ? (finishedSources / sourceList.length) * 100 : 0;

  return (
    <Surface
      variant={isDone ? 'gradient' : 'elevated'}
      elevation={isDone ? 3 : 2}
      className="motion-glide overflow-hidden"
    >
      {/* Decorative completion glow */}
      {isDone && summary && (
        <div
          aria-hidden
          className={cn(
            'pointer-events-none absolute inset-x-0 top-0 h-32 blur-3xl',
            summary.critical > 0
              ? 'bg-red-300/30 dark:bg-red-700/20'
              : summary.total > 0
                ? 'bg-amber-300/30 dark:bg-amber-700/20'
                : 'bg-emerald-300/30 dark:bg-emerald-700/20',
          )}
        />
      )}

      <SurfaceHeader>
        <div className="flex flex-1 items-center gap-3">
          <span
            className={cn(
              'inline-flex h-2.5 w-2.5 rounded-full',
              isRunning && 'bg-sky-500 pulse-dot text-sky-500',
              isDone && 'bg-emerald-500',
              isError && 'bg-red-500',
            )}
            aria-hidden
          />
          <div className="min-w-0 flex-1">
            <p className="text-sm font-semibold text-hcl-navy">{phaseLabel}</p>
            <p className="font-metric mt-0.5 text-[11px] tabular-nums text-hcl-muted">
              {components > 0 && (
                <>
                  <strong className="text-hcl-navy">{components.toLocaleString()}</strong> components
                </>
              )}
              {components > 0 && elapsedMs > 0 && ' · '}
              {elapsedMs > 0 && (
                <>
                  Elapsed <strong className="text-hcl-navy">{formatElapsed(elapsedMs)}</strong>
                </>
              )}
              {finishedSources > 0 && (
                <>
                  {' · '}
                  {finishedSources}/{sourceList.length} sources
                </>
              )}
            </p>
          </div>
          {isRunning && onCancel && (
            <Button variant="ghost" size="sm" onClick={onCancel}>
              <X className="h-3.5 w-3.5" aria-hidden /> Cancel
            </Button>
          )}
        </div>
      </SurfaceHeader>

      {/* Aggregate progress bar */}
      {isRunning && sourceList.length > 0 && (
        <div className="px-6 pt-4">
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-border-subtle">
            <div
              className="h-full bg-gradient-to-r from-hcl-blue via-hcl-cyan to-emerald-400 transition-[width] duration-slower ease-spring"
              style={{ width: `${progressPct}%` }}
            />
          </div>
        </div>
      )}

      <SurfaceContent>
        {/* Per-source cards */}
        {sourceList.length > 0 && (
          <ul className="grid grid-cols-1 gap-2 stagger sm:grid-cols-2 lg:grid-cols-4">
            {sourceList.map((src) => (
              <SourceLiveCard key={src.name} source={src} />
            ))}
          </ul>
        )}

        {/* Parsing-only state */}
        {phase === 'parsing' && sourceList.every((s) => s.status === 'pending') && (
          <p className="mt-3 inline-flex items-center gap-2 text-sm text-hcl-muted">
            <Loader2 className="h-4 w-4 animate-spin text-hcl-blue motion-reduce:animate-none" aria-hidden />
            Parsing SBOM and preparing queries…
          </p>
        )}

        {/* Error state */}
        {isError && error && (
          <div className="mt-4 space-y-3">
            <Alert variant="error" title="Analysis interrupted">
              {error}
            </Alert>
            <p className="flex items-start gap-1.5 text-xs leading-relaxed text-hcl-muted">
              <AlertTriangle className="h-3.5 w-3.5 mt-0.5" aria-hidden />
              <span>
                The live stream was cut, but the server may still finish the run. Check{' '}
                <Link
                  href="/analysis?tab=runs"
                  className="font-medium text-primary underline hover:text-hcl-dark"
                >
                  Analysis runs
                </Link>{' '}
                in a moment for a new entry.
              </span>
            </p>
          </div>
        )}

        {/* Animated completion summary */}
        {isDone && summary && (
          <div className="mt-5 space-y-4 motion-rise">
            <AnimatedSeverityBar
              counts={{
                critical: summary.critical,
                high: summary.high,
                medium: summary.medium,
                low: summary.low,
                unknown: summary.unknown,
              }}
              triggerKey={runId ?? 'done'}
            />
            <div className="grid grid-cols-3 gap-2 sm:grid-cols-6">
              {[
                { label: 'Total', value: summary.total, tone: 'text-hcl-navy' },
                { label: 'Critical', value: summary.critical, tone: 'text-red-700 dark:text-red-300' },
                { label: 'High', value: summary.high, tone: 'text-orange-700 dark:text-orange-300' },
                { label: 'Medium', value: summary.medium, tone: 'text-amber-700 dark:text-amber-300' },
                { label: 'Low', value: summary.low, tone: 'text-sky-700 dark:text-sky-300' },
                { label: 'Unknown', value: summary.unknown, tone: 'text-hcl-muted' },
              ].map(({ label, value, tone }) => (
                <div
                  key={label}
                  className="rounded-lg border border-border-subtle bg-surface px-3 py-2 text-center"
                >
                  <p className="text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
                    {label}
                  </p>
                  <p className={cn('font-metric mt-0.5 text-xl font-bold tabular-nums', tone)}>
                    {value.toLocaleString()}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}
      </SurfaceContent>

      <SurfaceFooter>
        <span className="mr-auto font-metric text-[11px] tabular-nums text-hcl-muted">
          {isDone && runId && (
            <>
              Run #<strong className="text-hcl-navy">{runId}</strong> · {formatDuration(elapsedMs)}
            </>
          )}
        </span>
        <div className="flex items-center gap-2">
          {(isDone || isError) && onReset && (
            <Button variant="secondary" size="sm" onClick={onReset}>
              Run again
            </Button>
          )}
          {isDone && runId && (
            <Button
              size="sm"
              glow
              onClick={() => router.push(`/analysis/${runId}`)}
            >
              View findings
              <ArrowRight className="h-4 w-4" aria-hidden />
            </Button>
          )}
        </div>
      </SurfaceFooter>
    </Surface>
  );
}
