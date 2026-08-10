'use client';

import { Suspense, useMemo, useState } from 'react';
import Link from 'next/link';
import { useSearchParams, useRouter } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import {
  ArrowDownRight,
  ArrowLeft,
  ArrowRight,
  ArrowUpRight,
  GitCompareArrows,
  Minus,
  MinusCircle,
  PlusCircle,
  Search,
  Shuffle,
  type LucideIcon,
} from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Alert } from '@/components/ui/Alert';
import { Surface, SurfaceContent, SurfaceHeader } from '@/components/ui/Surface';
import { Motion } from '@/components/ui/Motion';
import { EmptyState } from '@/components/ui/EmptyState';
import { Skeleton, SkeletonText } from '@/components/ui/Spinner';
import { compareRuns } from '@/lib/api';
import { cn, formatDate } from '@/lib/utils';

function parseRunId(value: string | null): number | null {
  if (!value) return null;
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? n : null;
}

function CompareRunsPageInner() {
  const params = useSearchParams();
  const router = useRouter();

  const runA = parseRunId(params.get('run_a'));
  const runB = parseRunId(params.get('run_b'));
  const canQuery = runA !== null && runB !== null && runA !== runB;

  const { data, isLoading, error } = useQuery({
    queryKey: ['compare-runs', runA, runB],
    queryFn: ({ signal }) => compareRuns(runA as number, runB as number, signal),
    enabled: canQuery,
  });

  return (
    <div className="flex flex-1 flex-col">
      <TopBar
        title="Compare runs"
        subtitle={canQuery ? `Run #${runA} vs Run #${runB}` : 'Diff two analysis runs'}
        breadcrumbs={[
          { label: 'Analysis Runs', href: '/analysis' },
          { label: 'Compare' },
        ]}
      />
      <div className="space-y-6 p-6">
        <button
          onClick={() => router.back()}
          className="inline-flex items-center gap-2 text-sm text-hcl-muted transition-colors hover:text-hcl-navy"
        >
          <ArrowLeft className="h-4 w-4" /> Back
        </button>

        {!canQuery && (
          <Surface variant="elevated">
            <SurfaceContent className="py-12">
              <EmptyState
                illustration="generic"
                title="No runs selected"
                description={
                  <>
                    Open this page with{' '}
                    <code className="font-mono rounded bg-surface-muted px-1.5 py-0.5 text-[11px]">
                      ?run_a=&lt;id&gt;&amp;run_b=&lt;id&gt;
                    </code>
                    , or pick exactly two runs on the{' '}
                    <Link href="/analysis" className="font-medium text-primary hover:underline">
                      Analysis Runs
                    </Link>{' '}
                    page and click <span className="font-medium">Compare</span>.
                  </>
                }
              />
            </SurfaceContent>
          </Surface>
        )}

        {canQuery && isLoading && <CompareSkeleton />}

        {canQuery && error && (
          <Alert variant="error" title="Could not compare runs">
            {(error as Error).message}
          </Alert>
        )}

        {canQuery && data && <CompareBody data={data} />}
      </div>
    </div>
  );
}

// ─── Body ────────────────────────────────────────────────────────────────────

function CompareBody({ data }: { data: NonNullable<Awaited<ReturnType<typeof compareRuns>>> }) {
  const [filter, setFilter] = useState('');
  const trimmed = filter.trim().toLowerCase();

  const newCount = data.new_findings.length;
  const resolvedCount = data.resolved_findings.length;
  const commonCount = data.common_findings.length;
  const total = newCount + resolvedCount + commonCount || 1;

  const newWidth = (newCount / total) * 100;
  const resolvedWidth = (resolvedCount / total) * 100;
  const commonWidth = (commonCount / total) * 100;

  const severityRows = [
    { label: 'Critical', delta: data.severity_delta.critical, dot: '#C0392B' },
    { label: 'High', delta: data.severity_delta.high, dot: '#D4680A' },
    { label: 'Medium', delta: data.severity_delta.medium, dot: '#B8860B' },
    { label: 'Low', delta: data.severity_delta.low, dot: '#0067B1' },
  ];

  const filterList = (items: string[]) =>
    trimmed ? items.filter((id) => id.toLowerCase().includes(trimmed)) : items;

  return (
    <>
      {/* Hero strip — Run A → Run B */}
      <Motion preset="rise">
        <Surface variant="gradient" elevation={3} className="relative overflow-hidden p-6">
          <div
            aria-hidden
            className="pointer-events-none absolute -right-24 -top-24 h-64 w-64 rounded-full bg-hcl-cyan/20 blur-3xl"
          />
          <div className="relative grid grid-cols-1 gap-4 lg:grid-cols-[1fr_auto_1fr] lg:items-center">
            <RunHeader run={data.run_a} label="Run A" align="left" />
            <div
              aria-hidden
              className="flex items-center justify-center text-hcl-muted"
            >
              <ArrowRight className="h-5 w-5" />
            </div>
            <RunHeader run={data.run_b} label="Run B" align="right" />
          </div>

          {/* Distribution bar — proportional segments for new / resolved / common */}
          <div className="relative mt-5 space-y-2">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
              Finding distribution
            </p>
            <div
              role="img"
              aria-label={`New ${newCount}, Resolved ${resolvedCount}, Common ${commonCount}`}
              className="flex h-3 w-full overflow-hidden rounded-full bg-border-subtle"
            >
              {newCount > 0 && (
                <div
                  className="h-full bg-red-500 transition-[width] duration-slower ease-spring motion-reduce:transition-none"
                  style={{ width: `${newWidth}%` }}
                  title={`${newCount} new in Run B`}
                />
              )}
              {commonCount > 0 && (
                <div
                  className="h-full bg-slate-400 transition-[width] duration-slower ease-spring motion-reduce:transition-none"
                  style={{ width: `${commonWidth}%` }}
                  title={`${commonCount} common to both runs`}
                />
              )}
              {resolvedCount > 0 && (
                <div
                  className="h-full bg-emerald-500 transition-[width] duration-slower ease-spring motion-reduce:transition-none"
                  style={{ width: `${resolvedWidth}%` }}
                  title={`${resolvedCount} resolved in Run B`}
                />
              )}
            </div>
            <ul className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-hcl-muted">
              <li className="inline-flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-red-500" aria-hidden />
                New: <strong className="text-hcl-navy">{newCount.toLocaleString()}</strong>
              </li>
              <li className="inline-flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-slate-400" aria-hidden />
                Common: <strong className="text-hcl-navy">{commonCount.toLocaleString()}</strong>
              </li>
              <li className="inline-flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-emerald-500" aria-hidden />
                Resolved: <strong className="text-hcl-navy">{resolvedCount.toLocaleString()}</strong>
              </li>
            </ul>
          </div>
        </Surface>
      </Motion>

      {/* Summary tiles */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3 stagger">
        <SummaryTile
          label="New in Run B"
          count={newCount}
          tone="negative"
          Icon={PlusCircle}
        />
        <SummaryTile
          label="Resolved in Run B"
          count={resolvedCount}
          tone="positive"
          Icon={MinusCircle}
        />
        <SummaryTile
          label="Common"
          count={commonCount}
          tone="neutral"
          Icon={Shuffle}
        />
      </div>

      {/* Severity delta */}
      <Motion preset="rise" delay={80}>
        <Surface variant="elevated">
          <SurfaceHeader>
            <div>
              <h3 className="text-base font-semibold text-hcl-navy">Severity delta (B − A)</h3>
              <p className="mt-0.5 text-xs text-hcl-muted">
                Negative numbers mean Run B improved on that severity.
              </p>
            </div>
          </SurfaceHeader>
          <SurfaceContent>
            <ul className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              {severityRows.map((row) => (
                <SeverityDelta key={row.label} {...row} />
              ))}
            </ul>
          </SurfaceContent>
        </Surface>
      </Motion>

      {/* Filter bar */}
      <div className="relative">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-hcl-muted" aria-hidden />
        <input
          type="search"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter all three lists by vuln ID…"
          aria-label="Filter findings by id"
          className="h-10 w-full rounded-lg border border-border bg-surface pl-9 pr-3 text-sm text-hcl-navy placeholder:text-hcl-muted focus-visible:border-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/30"
        />
      </div>

      {/* Three lists */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3 stagger">
        <FindingsList
          title="New in Run B"
          items={filterList(data.new_findings)}
          rawCount={newCount}
          tone="negative"
          Icon={PlusCircle}
          emptyMsg="No new findings."
        />
        <FindingsList
          title="Resolved in Run B"
          items={filterList(data.resolved_findings)}
          rawCount={resolvedCount}
          tone="positive"
          Icon={MinusCircle}
          emptyMsg="Nothing was resolved."
        />
        <FindingsList
          title="Common to both runs"
          items={filterList(data.common_findings)}
          rawCount={commonCount}
          tone="neutral"
          Icon={GitCompareArrows}
          emptyMsg="No overlap between runs."
        />
      </div>
    </>
  );
}

// ─── Helper components ───────────────────────────────────────────────────────

interface RunHeaderProps {
  run: { id: number; sbom_name: string | null; completed_on: string | null };
  label: string;
  align: 'left' | 'right';
}

function RunHeader({ run, label, align }: RunHeaderProps) {
  return (
    <div
      className={cn(
        'min-w-0',
        align === 'right' && 'lg:text-right',
      )}
    >
      <p className="text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
        {label}
      </p>
      <h3 className="mt-1 truncate text-display-sm font-semibold text-hcl-navy">
        <Link href={`/analysis/${run.id}`} className="hover:text-primary hover:underline">
          #{run.id}
        </Link>
      </h3>
      <p className="font-metric mt-0.5 truncate text-xs tabular-nums text-hcl-muted">
        {run.sbom_name ?? '—'}
      </p>
      <p className="font-metric text-[11px] tabular-nums text-hcl-muted">
        {formatDate(run.completed_on)}
      </p>
    </div>
  );
}

interface SummaryTileProps {
  label: string;
  count: number;
  tone: 'positive' | 'negative' | 'neutral';
  Icon: LucideIcon;
}

function SummaryTile({ label, count, tone, Icon }: SummaryTileProps) {
  const styles = {
    positive: {
      ring: 'ring-emerald-200/70 dark:ring-emerald-900/60',
      iconBg: 'bg-emerald-50 dark:bg-emerald-950/40',
      iconText: 'text-emerald-600 dark:text-emerald-400',
      glow: count > 0 ? 'shadow-glow-success' : '',
    },
    negative: {
      ring: 'ring-red-200/70 dark:ring-red-900/60',
      iconBg: 'bg-red-50 dark:bg-red-950/40',
      iconText: 'text-red-600 dark:text-red-400',
      glow: count > 0 ? 'shadow-glow-critical' : '',
    },
    neutral: {
      ring: 'ring-border-subtle',
      iconBg: 'bg-surface-muted',
      iconText: 'text-hcl-muted',
      glow: '',
    },
  }[tone];

  return (
    <Surface
      variant="elevated"
      elevation={2}
      className={cn('relative overflow-hidden p-5 ring-1', styles.ring, styles.glow)}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
            {label}
          </p>
          <p className="font-metric mt-1 text-3xl font-bold tabular-nums text-hcl-navy">
            {count.toLocaleString()}
          </p>
        </div>
        <span className={cn('flex h-10 w-10 shrink-0 items-center justify-center rounded-lg', styles.iconBg)}>
          <Icon className={cn('h-5 w-5', styles.iconText)} aria-hidden />
        </span>
      </div>
    </Surface>
  );
}

interface SeverityDeltaProps {
  label: string;
  delta: number;
  dot: string;
}

function SeverityDelta({ label, delta, dot }: SeverityDeltaProps) {
  const Icon = delta > 0 ? ArrowUpRight : delta < 0 ? ArrowDownRight : Minus;
  // For severity, +delta means MORE findings → bad. -delta means improvement → good.
  const tone =
    delta > 0
      ? 'text-red-700 dark:text-red-300'
      : delta < 0
        ? 'text-emerald-700 dark:text-emerald-300'
        : 'text-hcl-muted';

  return (
    <li className="rounded-lg border border-border-subtle bg-surface px-3 py-3 text-center">
      <p className="inline-flex items-center justify-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
        <span className="h-2 w-2 rounded-full" style={{ backgroundColor: dot }} aria-hidden />
        {label}
      </p>
      <p className={cn('font-metric mt-1.5 inline-flex items-center justify-center gap-1 text-2xl font-bold tabular-nums', tone)}>
        <Icon className="h-4 w-4" aria-hidden />
        {delta > 0 ? `+${delta}` : delta}
      </p>
    </li>
  );
}

interface FindingsListProps {
  title: string;
  items: string[];
  rawCount: number;
  tone: 'positive' | 'negative' | 'neutral';
  Icon: LucideIcon;
  emptyMsg: string;
}

function FindingsList({ title, items, rawCount, tone, Icon, emptyMsg }: FindingsListProps) {
  const styles = {
    positive: 'text-emerald-700 dark:text-emerald-300',
    negative: 'text-red-700 dark:text-red-300',
    neutral: 'text-hcl-navy',
  }[tone];

  return (
    <Surface variant="elevated" elevation={1}>
      <SurfaceHeader>
        <div className="flex items-center gap-2">
          <Icon className={cn('h-4 w-4', styles)} aria-hidden />
          <h3 className={cn('text-sm font-semibold', styles)}>
            {title}
            <span className="font-metric ml-1.5 text-xs font-normal tabular-nums text-hcl-muted">
              {items.length === rawCount
                ? items.length.toLocaleString()
                : `${items.length.toLocaleString()} / ${rawCount.toLocaleString()}`}
            </span>
          </h3>
        </div>
      </SurfaceHeader>
      <SurfaceContent className="px-2 py-2">
        {items.length === 0 ? (
          <p className="px-2 py-6 text-center text-sm text-hcl-muted">{emptyMsg}</p>
        ) : (
          <ul className="max-h-80 overflow-y-auto">
            {items.map((id) => {
              const url =
                id.startsWith('CVE-')
                  ? `https://nvd.nist.gov/vuln/detail/${id}`
                  : id.startsWith('GHSA-')
                    ? `https://github.com/advisories/${id}`
                    : null;
              return (
                <li key={id}>
                  {url ? (
                    <a
                      href={url}
                      target="_blank"
                      rel="noopener noreferrer"
                      title={id}
                      className="block truncate rounded px-2 py-1 font-mono text-xs text-hcl-navy transition-colors hover:bg-primary/5 hover:text-primary focus-visible:outline-none focus-visible:bg-primary/10"
                    >
                      {id}
                    </a>
                  ) : (
                    <span className="block truncate rounded px-2 py-1 font-mono text-xs text-hcl-navy">
                      {id}
                    </span>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </SurfaceContent>
    </Surface>
  );
}

function CompareSkeleton() {
  return (
    <div className="space-y-6">
      <Surface variant="elevated">
        <SurfaceContent>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_auto_1fr] lg:items-center">
            <div className="space-y-2">
              <Skeleton className="h-3 w-12" />
              <Skeleton className="h-7 w-24" />
              <Skeleton className="h-3 w-40" />
            </div>
            <Skeleton className="h-5 w-5 rounded-full" />
            <div className="space-y-2 lg:items-end">
              <Skeleton className="h-3 w-12" />
              <Skeleton className="h-7 w-24" />
              <Skeleton className="h-3 w-40" />
            </div>
          </div>
          <div className="mt-5">
            <Skeleton className="h-3 w-full" />
          </div>
        </SurfaceContent>
      </Surface>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        {[0, 1, 2].map((i) => (
          <Surface key={i} variant="elevated">
            <SurfaceContent>
              <Skeleton className="h-3 w-1/3" />
              <Skeleton className="mt-2 h-7 w-1/4" />
            </SurfaceContent>
          </Surface>
        ))}
      </div>
      <Surface variant="elevated">
        <SurfaceContent>
          <SkeletonText lines={4} />
        </SurfaceContent>
      </Surface>
    </div>
  );
}

// ─── Page wrapper ────────────────────────────────────────────────────────────

export default function CompareRunsPage() {
  return (
    <Suspense
      fallback={
        <div className="flex flex-1 flex-col">
          <TopBar
            title="Compare runs"
            breadcrumbs={[
              { label: 'Analysis Runs', href: '/analysis' },
              { label: 'Compare' },
            ]}
          />
          <div className="p-6">
            <CompareSkeleton />
          </div>
        </div>
      }
    >
      <CompareRunsPageInner />
    </Suspense>
  );
}
