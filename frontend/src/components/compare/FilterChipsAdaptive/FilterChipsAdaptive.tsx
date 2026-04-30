'use client';

import { Flame, Wrench, X } from 'lucide-react';
import { cn } from '@/lib/utils';
import type {
  FindingChangeKind,
  FindingDiffRow,
  PostureDelta,
} from '@/types/compare';

interface Props {
  rows: FindingDiffRow[];
  posture: PostureDelta;
  changeKinds: Set<FindingChangeKind>;
  toggleChangeKind: (k: FindingChangeKind) => void;
  severities: Set<string>;
  toggleSeverity: (s: string) => void;
  kevOnly: boolean;
  setKevOnly: (v: boolean) => void;
  fixAvailable: boolean;
  setFixAvailable: (v: boolean) => void;
  showUnchanged: boolean;
  setShowUnchanged: (v: boolean) => void;
  /** Number of rows currently visible after all filters. */
  visibleCount: number;
  onClearAll: () => void;
}

const SEVERITY_BUTTONS: Array<{ key: string; label: string; activeCls: string }> = [
  { key: 'critical', label: 'Critical', activeCls: 'border-red-300 bg-red-50 text-red-900' },
  { key: 'high', label: 'High', activeCls: 'border-orange-300 bg-orange-50 text-orange-900' },
  { key: 'medium', label: 'Medium', activeCls: 'border-amber-300 bg-amber-50 text-amber-900' },
  { key: 'low', label: 'Low', activeCls: 'border-blue-200 bg-blue-50 text-blue-900' },
];

const DEFAULT_CHANGE_KINDS = new Set<FindingChangeKind>([
  'added',
  'resolved',
  'severity_changed',
]);
const DEFAULT_SEVERITIES = new Set<string>(['critical', 'high', 'medium', 'low', 'unknown']);

/**
 * Adaptive filter chip row.
 *
 *   - Chips representing zero rows in the current diff dim to 60% opacity
 *     (still clickable; tooltip explains).
 *   - Active chips show an inline `×` so the user can remove them
 *     individually without juggling the cluster.
 *   - "Clear all" appears only when ≥ 1 filter is non-default.
 *   - Right-aligned status line: "Showing X of Y findings (filtered)".
 */
export function FilterChipsAdaptive(props: Props) {
  const {
    rows,
    posture,
    changeKinds,
    toggleChangeKind,
    severities,
    toggleSeverity,
    kevOnly,
    setKevOnly,
    fixAvailable,
    setFixAvailable,
    showUnchanged,
    setShowUnchanged,
    visibleCount,
    onClearAll,
  } = props;

  const totalRowsForVisibility = rows.filter((r) => r.change_kind !== 'unchanged').length;
  const hasNonDefaultFilter = isFiltered({
    changeKinds,
    severities,
    kevOnly,
    fixAvailable,
    showUnchanged,
  });

  // Per-severity counts in the current diff (drives dim-when-zero).
  const sevCounts = new Map<string, number>();
  for (const r of rows) {
    if (r.change_kind === 'unchanged' && !showUnchanged) continue;
    const sev = (r.change_kind === 'resolved' ? r.severity_a : r.severity_b ?? r.severity_a) ?? 'unknown';
    sevCounts.set(sev, (sevCounts.get(sev) ?? 0) + 1);
  }
  const kevCount = rows.filter((r) => r.kev_current && r.change_kind !== 'unchanged').length;
  const fixCount = rows.filter((r) => r.fix_available && r.change_kind !== 'unchanged').length;

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-1.5">
        <Chip
          active={changeKinds.has('added')}
          onToggle={() => toggleChangeKind('added')}
          activeCls="border-red-300 bg-red-50 text-red-900"
          count={posture.findings_added_count}
          label={`+ Added (${posture.findings_added_count})`}
        />
        <Chip
          active={changeKinds.has('resolved')}
          onToggle={() => toggleChangeKind('resolved')}
          activeCls="border-emerald-300 bg-emerald-50 text-emerald-900"
          count={posture.findings_resolved_count}
          label={`− Resolved (${posture.findings_resolved_count})`}
        />
        <Chip
          active={changeKinds.has('severity_changed')}
          onToggle={() => toggleChangeKind('severity_changed')}
          activeCls="border-amber-300 bg-amber-50 text-amber-900"
          count={posture.findings_severity_changed_count}
          label={`↕ Severity (${posture.findings_severity_changed_count})`}
        />
        <span className="mx-1 h-4 w-px bg-border-subtle" aria-hidden />
        {SEVERITY_BUTTONS.map((s) => (
          <Chip
            key={s.key}
            active={severities.has(s.key)}
            onToggle={() => toggleSeverity(s.key)}
            activeCls={s.activeCls}
            count={sevCounts.get(s.key) ?? 0}
            label={s.label}
          />
        ))}
        <span className="mx-1 h-4 w-px bg-border-subtle" aria-hidden />
        <Chip
          active={kevOnly}
          onToggle={() => setKevOnly(!kevOnly)}
          activeCls="border-red-400 bg-red-100 text-red-900"
          count={kevCount}
          ariaLabel="Show only findings currently in CISA KEV"
          label={
            <>
              <Flame className="h-3 w-3" aria-hidden /> KEV
            </>
          }
        />
        <Chip
          active={fixAvailable}
          onToggle={() => setFixAvailable(!fixAvailable)}
          activeCls="border-emerald-300 bg-emerald-50 text-emerald-900"
          count={fixCount}
          ariaLabel="Show only findings with a known fix"
          label={
            <>
              <Wrench className="h-3 w-3" aria-hidden /> Fix-available
            </>
          }
        />
        <Chip
          active={showUnchanged}
          onToggle={() => setShowUnchanged(!showUnchanged)}
          activeCls="border-slate-400 bg-slate-100 text-slate-900"
          count={posture.findings_unchanged_count}
          label="Show unchanged"
        />
        {hasNonDefaultFilter && (
          <button
            type="button"
            onClick={onClearAll}
            className="ml-1 text-[11px] text-hcl-blue underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/30"
          >
            Clear all
          </button>
        )}
        <span className="ml-auto text-[11px] tabular-nums text-hcl-muted">
          Showing {visibleCount.toLocaleString()} of{' '}
          {totalRowsForVisibility.toLocaleString()} findings
          {hasNonDefaultFilter && (
            <span className="ml-1 italic">(filtered)</span>
          )}
        </span>
      </div>
    </div>
  );
}

interface ChipProps {
  active: boolean;
  onToggle: () => void;
  activeCls: string;
  count: number;
  /** Visible inner content. Pass a fragment for icon+text. */
  label: React.ReactNode;
  ariaLabel?: string;
}

function Chip({ active, onToggle, activeCls, count, label, ariaLabel }: ChipProps) {
  const dim = !active && count === 0;
  return (
    <button
      type="button"
      onClick={onToggle}
      aria-pressed={active}
      aria-label={ariaLabel}
      title={dim ? '0 items match this filter in the current diff' : undefined}
      className={cn(
        'inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors',
        active
          ? activeCls
          : 'border-border bg-surface text-hcl-muted hover:bg-surface-muted',
        dim && 'opacity-50',
      )}
    >
      {label}
      {active && (
        <span
          aria-hidden
          className="-mr-0.5 ml-0.5 inline-flex h-3 w-3 items-center justify-center"
        >
          <X className="h-2.5 w-2.5" />
        </span>
      )}
    </button>
  );
}

interface FilterState {
  changeKinds: Set<FindingChangeKind>;
  severities: Set<string>;
  kevOnly: boolean;
  fixAvailable: boolean;
  showUnchanged: boolean;
}

function isFiltered(state: FilterState): boolean {
  if (state.kevOnly || state.fixAvailable || state.showUnchanged) return true;
  if (state.changeKinds.size !== DEFAULT_CHANGE_KINDS.size) return true;
  for (const k of DEFAULT_CHANGE_KINDS) {
    if (!state.changeKinds.has(k)) return true;
  }
  if (state.severities.size !== DEFAULT_SEVERITIES.size) return true;
  for (const s of DEFAULT_SEVERITIES) {
    if (!state.severities.has(s)) return true;
  }
  return false;
}
