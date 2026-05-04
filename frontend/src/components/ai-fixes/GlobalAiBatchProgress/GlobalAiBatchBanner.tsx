'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { CheckCircle2, Loader2, Sparkles, XCircle } from 'lucide-react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  cancelRunAiBatch,
  cancelRunAiFixes,
  getRunAiBatch,
  getRunAiFixProgress,
} from '@/lib/api';
import type { AiBatchProgress } from '@/types/ai';
import { useTrackedAiBatches } from './useGlobalAiBatchProgress';
import { batchProgressQueryKey } from './AiBatchProgressProvider';
import type { AiBatchTrackingKey } from './AiBatchProgressContext';

const MAX_VISIBLE = 3;

function isTerminal(status: AiBatchProgress['status']): boolean {
  return status === 'complete' || status === 'failed' || status === 'cancelled';
}

function statusIcon(status: AiBatchProgress['status']) {
  if (status === 'complete') return <CheckCircle2 className="h-4 w-4 text-emerald-600" aria-hidden />;
  if (status === 'failed') return <XCircle className="h-4 w-4 text-red-600" aria-hidden />;
  if (status === 'cancelled') return <XCircle className="h-4 w-4 text-hcl-muted" aria-hidden />;
  return <Loader2 className="h-4 w-4 animate-spin text-primary" aria-hidden />;
}

function summaryLine(p: AiBatchProgress): string {
  const done = p.from_cache + p.generated + p.failed;
  const total = p.total > 0 ? p.total : done;
  const cost = `$${p.cost_so_far_usd.toFixed(4)}`;
  if (p.status === 'complete') {
    return `${total.toLocaleString()} fixes · ${cost} · ${p.from_cache.toLocaleString()} cached`;
  }
  if (p.status === 'failed') return p.last_error ?? 'AI generation failed';
  if (p.status === 'cancelled') return `Cancelled at ${done.toLocaleString()} / ${total.toLocaleString()}`;
  return `${done.toLocaleString()} / ${total.toLocaleString()} · ${cost}`;
}

function progressPct(p: AiBatchProgress): number {
  if (p.total <= 0) return 0;
  const done = p.from_cache + p.generated + p.failed;
  return Math.min(100, Math.round((done / p.total) * 100));
}

interface RowProps {
  entry: AiBatchTrackingKey;
  /** Render compactly when stacked behind a "+N more" cluster. */
  compact?: boolean;
}

function GlobalBatchRow({ entry, compact = false }: RowProps) {
  const qc = useQueryClient();
  const { runId, batchId, scopeLabel } = entry;
  const queryKey = batchProgressQueryKey(runId, batchId);
  const { data: progress } = useQuery<AiBatchProgress>({
    queryKey,
    queryFn: ({ signal }) => {
      if (batchId == null) return getRunAiFixProgress(runId, signal);
      return getRunAiBatch(runId, batchId, signal).then(
        (detail) => detail.progress as AiBatchProgress,
      );
    },
  });

  if (!progress) return null;

  const inFlight = !isTerminal(progress.status);
  const pct = progressPct(progress);
  // The banner row's scope label prefers the live progress payload
  // (which the worker may have refined) but falls back to whatever the
  // CTA registered at trigger time so the row never goes blank
  // mid-stream.
  const label = progress.scope_label ?? scopeLabel ?? null;

  const onCancel = async () => {
    try {
      if (batchId == null) {
        await cancelRunAiFixes(runId);
      } else {
        await cancelRunAiBatch(runId, batchId);
      }
      qc.invalidateQueries({ queryKey });
    } catch {
      /* user can retry — toast on the originating page already covers errors */
    }
  };

  return (
    <div
      role={progress.status === 'failed' ? 'alert' : 'status'}
      aria-live="polite"
      className="flex items-center gap-3 rounded-lg border border-border-subtle bg-surface px-3 py-2 shadow-card dark:bg-surface"
      data-testid={
        batchId == null
          ? `global-ai-batch-row-${runId}`
          : `global-ai-batch-row-${runId}-${batchId}`
      }
    >
      {statusIcon(progress.status)}
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <Sparkles className="h-3 w-3 shrink-0 text-primary" aria-hidden />
          <Link
            href={`/analysis/${runId}`}
            className="truncate text-xs font-semibold text-hcl-navy hover:underline"
          >
            Run #{runId}
          </Link>
          {label ? (
            <span className="truncate rounded-md bg-surface-muted px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-hcl-muted">
              {label}
            </span>
          ) : null}
          {!compact ? (
            <span className="truncate text-[11px] text-hcl-muted">
              {summaryLine(progress)}
            </span>
          ) : null}
        </div>
        {!compact && inFlight && progress.total > 0 ? (
          <div className="mt-1 h-1 overflow-hidden rounded-full bg-surface-muted">
            <div
              className="h-full bg-primary transition-[width] duration-base"
              style={{ width: `${pct}%` }}
              aria-hidden
            />
          </div>
        ) : null}
      </div>
      {inFlight && !compact ? (
        <button
          type="button"
          onClick={onCancel}
          className="shrink-0 rounded-md border border-border-subtle bg-surface px-2 py-1 text-[11px] font-medium text-hcl-navy hover:bg-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/30"
        >
          Cancel
        </button>
      ) : null}
    </div>
  );
}

/**
 * Renders inside the AppShell at the top of <main>. Persists across
 * route changes; up to MAX_VISIBLE rows show in full, additional batches
 * collapse behind a "+N more" affordance. When the user is on the
 * /analysis/[id] page that matches a tracked run, that run's batches
 * are hidden from the global banner — the page's own RunBatchProgress
 * is the canonical surface for them.
 *
 * Multi-batch (Phase 4): the same run may contribute multiple rows,
 * each labelled by its scope ("Critical", "KEV", "Selected (12)") so
 * they're distinguishable at a glance.
 */
export function GlobalAiBatchBanner() {
  const tracked = useTrackedAiBatches();
  const pathname = usePathname();

  if (tracked.length === 0) return null;

  // If the user is on /analysis/<id> for a tracked run, drop every
  // entry for that run so the page banner is the canonical surface.
  const onRunDetailMatch = pathname?.match(/^\/analysis\/(\d+)/);
  const currentRunId = onRunDetailMatch ? Number(onRunDetailMatch[1]) : null;
  const visible = tracked.filter((entry) => entry.runId !== currentRunId);

  if (visible.length === 0) return null;

  const head = visible.slice(0, MAX_VISIBLE);
  const overflow = visible.length - head.length;

  return (
    <div
      className="sticky top-0 z-20 space-y-1 border-b border-border-subtle bg-background/95 px-4 py-2 backdrop-blur supports-[backdrop-filter]:bg-background/80"
      aria-label="AI batch progress"
    >
      {head.map((entry) => (
        <GlobalBatchRow
          key={entry.batchId == null ? `legacy-${entry.runId}` : `${entry.runId}-${entry.batchId}`}
          entry={entry}
        />
      ))}
      {overflow > 0 ? (
        <p className="px-1 text-[11px] text-hcl-muted">
          +{overflow} more AI batch{overflow === 1 ? '' : 'es'} in progress
        </p>
      ) : null}
    </div>
  );
}
