import { runStatusDescription, runStatusShortLabel } from '@/lib/analysisRunStatusLabels';
import { cn } from '@/lib/utils';
import type { ReactNode } from 'react';

interface BadgeProps {
  children: ReactNode;
  variant?: 'default' | 'success' | 'error' | 'warning' | 'info' | 'gray';
  className?: string;
}

const variantClasses: Record<string, string> = {
  default: 'bg-hcl-light text-hcl-navy border-hcl-border',
  success:
    'bg-green-50 text-green-800 border-green-200 dark:bg-emerald-950/50 dark:text-emerald-200 dark:border-emerald-800',
  error: 'bg-red-50 text-red-800 border-red-200 dark:bg-red-950/50 dark:text-red-200 dark:border-red-800',
  warning:
    'bg-amber-50 text-amber-800 border-amber-200 dark:bg-amber-950/50 dark:text-amber-200 dark:border-amber-800',
  info: 'bg-hcl-light text-hcl-blue border-hcl-border',
  gray: 'bg-slate-100 text-slate-700 border-slate-200 dark:bg-slate-800 dark:text-slate-200 dark:border-slate-600',
};

const BASE =
  'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border whitespace-nowrap';

export function Badge({ children, variant = 'default', className }: BadgeProps) {
  return <span className={cn(BASE, variantClasses[variant], className)}>{children}</span>;
}

const severityMap: Record<string, { cls: string; dot: string; label: string }> = {
  CRITICAL: {
    cls: 'bg-red-50 text-red-900 border-red-300 dark:bg-red-950/60 dark:text-red-100 dark:border-red-700 font-semibold',
    dot: 'bg-red-600 dark:bg-red-400',
    label: 'Critical severity',
  },
  HIGH: {
    cls: 'bg-orange-50 text-orange-900 border-orange-300 dark:bg-orange-950/50 dark:text-orange-100 dark:border-orange-700 font-semibold',
    dot: 'bg-orange-500 dark:bg-orange-400',
    label: 'High severity',
  },
  MEDIUM: {
    cls: 'bg-amber-50 text-amber-900 border-amber-300 dark:bg-amber-950/50 dark:text-amber-100 dark:border-amber-700',
    dot: 'bg-amber-500 dark:bg-amber-400',
    label: 'Medium severity',
  },
  LOW: {
    cls: 'bg-hcl-light text-hcl-blue border-hcl-border',
    dot: 'bg-hcl-blue',
    label: 'Low severity',
  },
  UNKNOWN: {
    cls: 'bg-slate-100 text-slate-700 border-slate-200 dark:bg-slate-800 dark:text-slate-200 dark:border-slate-600',
    dot: 'bg-slate-400 dark:bg-slate-500',
    label: 'Unknown severity',
  },
};

export function SeverityBadge({ severity }: { severity: string }) {
  const key = severity?.toUpperCase() ?? 'UNKNOWN';
  const entry = severityMap[key] ?? severityMap.UNKNOWN;
  return (
    <span className={cn(BASE, 'gap-1.5', entry.cls)} aria-label={entry.label}>
      <span className={cn('h-1.5 w-1.5 rounded-full', entry.dot)} aria-hidden="true" />
      {severity}
    </span>
  );
}

const statusMap: Record<string, { cls: string; dot: string }> = {
  PASS: {
    cls: 'bg-green-50 text-green-800 border-green-200 dark:bg-emerald-950/50 dark:text-emerald-200 dark:border-emerald-800',
    dot: 'bg-green-500',
  },
  FAIL: {
    cls: 'bg-red-50 text-red-800 border-red-200 dark:bg-red-950/50 dark:text-red-200 dark:border-red-800',
    dot: 'bg-red-500',
  },
  PARTIAL: {
    cls: 'bg-amber-50 text-amber-800 border-amber-200 dark:bg-amber-950/50 dark:text-amber-200 dark:border-amber-800',
    dot: 'bg-amber-500',
  },
  ERROR: {
    cls: 'bg-red-50 text-red-800 border-red-200 dark:bg-red-950/50 dark:text-red-200 dark:border-red-800',
    dot: 'bg-red-500',
  },
  RUNNING: {
    cls: 'bg-hcl-light text-hcl-blue border-hcl-border',
    dot: 'bg-hcl-blue animate-pulse motion-reduce:animate-none',
  },
  PENDING: {
    cls: 'bg-slate-100 text-slate-600 border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-600',
    dot: 'bg-slate-400 dark:bg-slate-500',
  },
  NO_DATA: {
    cls: 'bg-slate-100 text-slate-700 border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-600',
    dot: 'bg-slate-400 dark:bg-slate-500',
  },
};

/**
 * Roadmap #1 — version-match trust signal for findings produced by the
 * NVD version-range filter. Collapses the seven-value backend literal
 * into two visual states the analyst actually acts on:
 *
 *   * "Version confirmed"  → success variant; the component's pinned
 *                            version was verified against the CVE's
 *                            affected range. ``matched_range`` is shown
 *                            as a tooltip so the analyst can see WHY.
 *   * "Not verified"       → muted/gray variant; the filter could not
 *                            confirm the version is in range and kept
 *                            the finding conservatively. The specific
 *                            reason is in the tooltip for the curious.
 *
 * Returns ``null`` when ``reason`` is null/undefined so rows from
 * flag-off scans look byte-identical to before. ``cursor-help`` plus
 * the ``title`` attribute give the tooltip without pulling in a
 * tooltip primitive — fine for a single-line hover hint.
 */
interface MatchReasonBadgeProps {
  reason: string | null | undefined;
  matchedRange?: string | null;
}

const MATCH_REASON_DETAIL: Record<string, string> = {
  version_unparseable:
    "Couldn't parse the component version under this ecosystem's rules",
  and_node_ambiguous:
    'CVE applies only under a specific platform — auto-verification unavailable',
  ecosystem_unsupported:
    'No version comparator for this ecosystem yet',
  no_configurations:
    'CVE has no version-range data — kept conservatively',
};

export function MatchReasonBadge({ reason, matchedRange }: MatchReasonBadgeProps) {
  if (!reason) return null;
  if (reason === 'matched') {
    const tooltip = matchedRange
      ? `Affected: ${matchedRange}`
      : 'Version confirmed in affected range';
    return (
      <span title={tooltip} className="cursor-help">
        <Badge variant="success">Version confirmed</Badge>
      </span>
    );
  }
  const detail = MATCH_REASON_DETAIL[reason] ?? `Match status: ${reason}`;
  return (
    <span title={detail} className="cursor-help">
      <Badge variant="gray">Not verified</Badge>
    </span>
  );
}

/**
 * Roadmap #3 — compact confidence display for the finding row.
 *
 * Renders a small, border-less, percentage-only number that sits
 * INLINE next to MatchReasonBadge in the severity cell — deliberately
 * NOT a third stacked badge (would clutter the cell). The colour band
 * is informational: green ≥ 70%, amber 40-70%, gray < 40%. Null
 * input renders nothing, preserving PR4's flag-off parity.
 *
 * The underlying backend value carries 3-decimal precision; the UI
 * rounds to whole percent — sub-score breakdown would warrant a
 * tooltip but the three sub-scores aren't persisted (migration 017
 * only added the final number). Tracked as a follow-up.
 */
interface MatchConfidenceChipProps {
  confidence: number | null | undefined;
}

export function MatchConfidenceChip({ confidence }: MatchConfidenceChipProps) {
  if (confidence == null) return null;
  const clamped = Math.max(0, Math.min(1, confidence));
  const pct = Math.round(clamped * 100);
  const tone =
    clamped >= 0.7
      ? 'text-emerald-700 dark:text-emerald-300'
      : clamped >= 0.4
        ? 'text-amber-700 dark:text-amber-300'
        : 'text-hcl-muted';
  return (
    <span
      title={`Match confidence ${pct}% — token-overlap of component identity vs CVE evidence, post strategy-floor.`}
      className={cn(
        'font-metric inline-flex cursor-help items-baseline tabular-nums',
        'text-[10px] font-semibold',
        tone,
      )}
      aria-label={`Match confidence ${pct} percent`}
    >
      {pct}%
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const key = status?.toUpperCase() ?? 'PENDING';
  const entry = statusMap[key] ?? statusMap.PENDING;
  const short = runStatusShortLabel(status);
  const help = runStatusDescription(status);
  return (
    <span
      className={cn(BASE, 'max-w-full cursor-help gap-1.5', entry.cls)}
      title={help}
      aria-label={help}
    >
      <span className={cn('h-1.5 w-1.5 shrink-0 rounded-full', entry.dot)} aria-hidden="true" />
      <span className="min-w-0 truncate">{short}</span>
    </span>
  );
}
