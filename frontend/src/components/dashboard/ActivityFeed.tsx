'use client';

import Link from 'next/link';
import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  ArrowUpRight,
  CheckCircle2,
  Clock,
  CircleDashed,
  FileText,
  ScanSearch,
  ShieldAlert,
  XCircle,
  type LucideIcon,
} from 'lucide-react';
import { Surface, SurfaceContent, SurfaceHeader } from '@/components/ui/Surface';
import { Skeleton } from '@/components/ui/Spinner';
import { EmptyState } from '@/components/ui/EmptyState';
import { getRecentSboms, getRuns } from '@/lib/api';
import { cn, formatDate } from '@/lib/utils';
import type { AnalysisRun, RecentSbom } from '@/types';

type FeedItem =
  | {
      kind: 'run';
      id: number;
      timestamp: string;
      run: AnalysisRun;
    }
  | {
      kind: 'upload';
      id: number;
      timestamp: string;
      sbom: RecentSbom;
    };

function formatRelative(input: string | null | undefined): string {
  if (!input) return '—';
  const date = new Date(input);
  if (Number.isNaN(date.getTime())) return '—';
  const diff = Date.now() - date.getTime();
  if (diff < 30_000) return 'just now';
  const minutes = Math.floor(diff / 60_000);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  const weeks = Math.floor(days / 7);
  if (weeks < 5) return `${weeks}w ago`;
  return formatDate(input);
}

// ADR-0001: FINDINGS replaces FAIL and paints amber (not red) — a successful
// scan that found vulns is not a pipeline failure. ERROR remains the only
// red status. Legacy keys (PASS/FAIL) kept for one deprecation cycle.
const _OK_GLYPH = { Icon: CheckCircle2, tone: 'text-emerald-600 dark:text-emerald-400', bg: 'bg-emerald-50 dark:bg-emerald-950/40', label: 'Clean' };
const _FINDINGS_GLYPH = { Icon: ShieldAlert, tone: 'text-amber-600 dark:text-amber-400', bg: 'bg-amber-50 dark:bg-amber-950/40', label: 'Findings detected' };
const statusGlyph: Record<
  AnalysisRun['run_status'],
  { Icon: LucideIcon; tone: string; bg: string; label: string }
> = {
  OK: _OK_GLYPH,
  PASS: _OK_GLYPH, // legacy alias
  FINDINGS: _FINDINGS_GLYPH,
  FAIL: _FINDINGS_GLYPH, // legacy alias
  PARTIAL: { Icon: CircleDashed, tone: 'text-amber-600 dark:text-amber-400', bg: 'bg-amber-50 dark:bg-amber-950/40', label: 'Partial' },
  ERROR: { Icon: XCircle, tone: 'text-red-600 dark:text-red-400', bg: 'bg-red-50 dark:bg-red-950/40', label: 'Errored' },
  RUNNING: { Icon: ScanSearch, tone: 'text-sky-600 dark:text-sky-400', bg: 'bg-sky-50 dark:bg-sky-950/40', label: 'Running' },
  PENDING: { Icon: Clock, tone: 'text-hcl-muted', bg: 'bg-surface-muted', label: 'Pending' },
  NO_DATA: { Icon: CircleDashed, tone: 'text-hcl-muted', bg: 'bg-surface-muted', label: 'No data' },
};

export function ActivityFeed() {
  const recentSbomsQuery = useQuery({
    queryKey: ['recent-sboms'],
    queryFn: ({ signal }) => getRecentSboms(8, signal),
  });

  const recentRunsQuery = useQuery({
    queryKey: ['recent-runs'],
    queryFn: ({ signal }) => getRuns({ page: 1, page_size: 12 }, signal),
  });

  const feed = useMemo<FeedItem[]>(() => {
    const items: FeedItem[] = [];
    for (const run of recentRunsQuery.data ?? []) {
      const ts = run.completed_on ?? run.started_on;
      if (!ts) continue;
      items.push({ kind: 'run', id: run.id, timestamp: ts, run });
    }
    for (const sbom of recentSbomsQuery.data ?? []) {
      items.push({ kind: 'upload', id: sbom.id, timestamp: sbom.created_on, sbom });
    }
    items.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    return items.slice(0, 10);
  }, [recentRunsQuery.data, recentSbomsQuery.data]);

  const isLoading = recentSbomsQuery.isLoading || recentRunsQuery.isLoading;

  return (
    <Surface variant="elevated">
      <SurfaceHeader>
        <div>
          <h3 className="text-base font-semibold text-hcl-navy">Recent activity</h3>
          <p className="mt-0.5 text-xs text-hcl-muted">
            Uploads, analysis runs, and status changes — newest first.
          </p>
        </div>
        <Link
          href="/sboms"
          className="inline-flex items-center gap-1 text-xs font-medium text-primary transition-colors hover:text-hcl-dark"
        >
          All SBOMs <ArrowUpRight className="h-3 w-3" aria-hidden />
        </Link>
      </SurfaceHeader>
      <SurfaceContent>
        {isLoading ? (
          <ul className="space-y-3">
            {[0, 1, 2, 3, 4].map((i) => (
              <li key={i} className="flex items-start gap-3">
                <Skeleton className="h-9 w-9 rounded-full" />
                <div className="flex-1 space-y-2">
                  <Skeleton className="h-3 w-3/4" />
                  <Skeleton className="h-2 w-1/2" />
                </div>
              </li>
            ))}
          </ul>
        ) : feed.length === 0 ? (
          <EmptyState
            illustration="no-sboms"
            title="No activity yet"
            description="Uploaded SBOMs and analysis runs will appear here."
            action={
              <Link
                href="/sboms"
                className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-white transition-all duration-base ease-spring hover:-translate-y-px hover:bg-hcl-dark hover:shadow-glow-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40"
              >
                Upload SBOM
              </Link>
            }
            compact
          />
        ) : (
          <ol className="relative space-y-1 stagger" aria-label="Recent activity timeline">
            {/* Vertical timeline rail */}
            <div
              aria-hidden="true"
              className="absolute left-[19px] top-2 bottom-2 w-px bg-gradient-to-b from-border-subtle via-border to-transparent"
            />
            {feed.map((item) => (
              <FeedRow key={`${item.kind}-${item.id}-${item.timestamp}`} item={item} />
            ))}
          </ol>
        )}
      </SurfaceContent>
    </Surface>
  );
}

function FeedRow({ item }: { item: FeedItem }) {
  if (item.kind === 'upload') {
    return (
      <li className="relative">
        <Link
          href={`/sboms/${item.sbom.id}`}
          className={cn(
            'group flex items-start gap-3 rounded-lg border border-transparent p-2 transition-all duration-base ease-spring',
            'hover:-translate-y-px hover:border-border-subtle hover:bg-surface-muted',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40',
          )}
        >
          <span
            aria-hidden
            className="relative z-10 flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-hcl-light text-hcl-blue ring-4 ring-surface"
          >
            <FileText className="h-4 w-4" />
          </span>
          <div className="min-w-0 flex-1 pt-1">
            <p className="truncate text-sm text-hcl-navy">
              <span className="font-medium">SBOM uploaded</span>
              <span className="text-hcl-muted"> · </span>
              <span className="text-hcl-muted group-hover:text-primary">
                {item.sbom.sbom_name}
              </span>
            </p>
            <p className="font-metric text-[11px] tabular-nums text-hcl-muted">
              {formatRelative(item.sbom.created_on)}
            </p>
          </div>
        </Link>
      </li>
    );
  }

  const { run } = item;
  const status = statusGlyph[run.run_status];
  const findingTotal = run.total_findings ?? 0;
  const isRunning = run.run_status === 'RUNNING' || run.run_status === 'PENDING';

  return (
    <li className="relative">
      <Link
        href={`/analysis/${run.id}`}
        className={cn(
          'group flex items-start gap-3 rounded-lg border border-transparent p-2 transition-all duration-base ease-spring',
          'hover:-translate-y-px hover:border-border-subtle hover:bg-surface-muted',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40',
        )}
      >
        <span
          aria-hidden
          className={cn(
            'relative z-10 flex h-9 w-9 shrink-0 items-center justify-center rounded-full ring-4 ring-surface',
            status.bg,
            status.tone,
            isRunning && 'pulse-dot',
          )}
        >
          <status.Icon className="h-4 w-4" />
        </span>
        <div className="min-w-0 flex-1 pt-1">
          <p className="truncate text-sm text-hcl-navy">
            <span className="font-medium">{status.label}</span>
            <span className="text-hcl-muted"> · </span>
            <span className="text-hcl-muted group-hover:text-primary">
              {run.sbom_name ?? `Run #${run.id}`}
            </span>
          </p>
          <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[11px] text-hcl-muted">
            <span className="font-metric tabular-nums">
              {formatRelative(run.completed_on ?? run.started_on)}
            </span>
            {findingTotal > 0 && (
              <>
                <span aria-hidden>·</span>
                <span className="font-metric">
                  <strong className="text-hcl-navy">{findingTotal.toLocaleString()}</strong> findings
                </span>
              </>
            )}
            {(run.critical_count ?? 0) > 0 && (
              <>
                <span aria-hidden>·</span>
                <span className="inline-flex items-center gap-1 font-metric text-red-700 dark:text-red-300">
                  <span className="h-1.5 w-1.5 rounded-full bg-red-600" aria-hidden />
                  {run.critical_count} critical
                </span>
              </>
            )}
          </div>
        </div>
      </Link>
    </li>
  );
}
