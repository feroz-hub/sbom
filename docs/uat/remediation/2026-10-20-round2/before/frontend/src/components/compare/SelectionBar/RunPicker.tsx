'use client';

import { useEffect, useId, useMemo, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Check, ChevronDown, Info, Loader2, Search } from 'lucide-react';
import { Surface } from '@/components/ui/Surface';
import { recentRuns, searchRuns } from '@/lib/api';
import { cn, formatDate } from '@/lib/utils';
import type { RunSummary } from '@/types/compare';
import { groupRunsForCompare } from './groupRunsForCompare';

interface RunPickerProps {
  label: string;
  selectedRunId: number | null;
  /**
   * Canonical summary for the currently-selected run. Comes from the parent
   * (compare query result, then the picker's own callback). Used for the
   * trigger label so users arriving via a shareable URL see the run name
   * even when the id isn't in the recent/search response.
   */
  selectedRunSummary?: RunSummary | null;
  onSelect: (run: RunSummary) => void;
  /**
   * The run picked in the OTHER picker. When provided, the dropdown is
   * grouped: other runs of the same logical SBOM appear at the top under
   * "Other runs of {name}", everything else under "Other SBOMs". The
   * paired run itself is excluded so the user can't land on a degenerate
   * self-compare.
   */
  pairedRun?: RunSummary | null;
  /**
   * Display name for the paired picker (e.g. "Run A" or "Run B"). Used in
   * the "Same project as {label}" filter chip copy. Defaults to "Run A"
   * since the most common workflow is Run A → Run B.
   */
  pairedRunLabel?: string;
  align?: 'left' | 'right';
}

/**
 * Typeahead Combobox built from existing primitives — no new shadcn dep.
 *
 * Default open: 20 most recent runs.
 * Type-ahead: 200ms debounced query against /api/runs/search.
 * Keyboard: ↑/↓ navigate, Enter select, Esc close.
 *
 * When a paired run is provided, the listbox is split into two
 * ``role="group"`` sections so the most likely comparison target — another
 * run of the same logical SBOM — is surfaced at the top. See
 * ``groupRunsForCompare`` for the grouping rules.
 */
export function RunPicker({
  label,
  selectedRunId,
  selectedRunSummary,
  onSelect,
  pairedRun,
  pairedRunLabel = 'Run A',
  align = 'left',
}: RunPickerProps) {
  const inputId = useId();
  const listboxId = useId();
  const primaryHeadingId = useId();
  const otherHeadingId = useId();
  const [open, setOpen] = useState(false);
  const [needle, setNeedle] = useState('');
  const [activeIndex, setActiveIndex] = useState(-1);
  const [sameProjectOnly, setSameProjectOnly] = useState(false);
  const wrapRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);

  // Debounce the search query so we don't hammer the backend on every keystroke.
  const [debounced, setDebounced] = useState('');
  useEffect(() => {
    const t = setTimeout(() => setDebounced(needle.trim()), 200);
    return () => clearTimeout(t);
  }, [needle]);

  const recentQuery = useQuery({
    queryKey: ['compare', 'picker', 'recent'],
    queryFn: ({ signal }) => recentRuns(20, signal),
    enabled: open && debounced === '',
    staleTime: 5 * 60 * 1000,
  });
  const searchQuery = useQuery({
    queryKey: ['compare', 'picker', 'search', debounced],
    queryFn: ({ signal }) => searchRuns(debounced, 20, signal),
    enabled: open && debounced !== '',
    staleTime: 5 * 60 * 1000,
  });
  const isLoading = recentQuery.isLoading || searchQuery.isLoading;
  const baseOptions = (debounced ? searchQuery.data : recentQuery.data) ?? [];

  const pairedProjectId = pairedRun?.project_id ?? null;

  // Optional same-project filter is applied BEFORE grouping so that the
  // primary/other split only contains runs the user hasn't filtered out.
  const filteredOptions = useMemo(() => {
    if (!sameProjectOnly || pairedProjectId == null) return baseOptions;
    return baseOptions.filter((r) => r.project_id === pairedProjectId);
  }, [baseOptions, sameProjectOnly, pairedProjectId]);

  // Split into "Other runs of {paired SBOM}" and "Other SBOMs". When no
  // paired run is set everything lands in `other` and the picker renders
  // a flat list (legacy behavior preserved).
  const grouped = useMemo(
    () => groupRunsForCompare(filteredOptions, pairedRun ?? null),
    [filteredOptions, pairedRun],
  );

  // Single flat list backs keyboard navigation and aria-activedescendant.
  // Order matches visual order: primary first, then other.
  const flatOptions = useMemo(
    () => [...grouped.primary, ...grouped.other],
    [grouped],
  );

  // Prefer the parent-supplied summary so the trigger label is correct on
  // shareable URLs where the run id may not be in the recent/search list.
  // Fall back to the loaded options for the case where a run was just picked.
  const selectedRun = useMemo(() => {
    if (selectedRunId == null) return undefined;
    if (selectedRunSummary && selectedRunSummary.id === selectedRunId) {
      return selectedRunSummary;
    }
    return baseOptions.find((r) => r.id === selectedRunId);
  }, [baseOptions, selectedRunId, selectedRunSummary]);

  // Close on outside click.
  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  // Reset the active index whenever the option set changes — otherwise
  // ArrowDown/Enter could land on a stale index after grouping reshuffles
  // the list (e.g. when the user toggles "Same project as Run A").
  useEffect(() => {
    setActiveIndex(flatOptions.length > 0 ? 0 : -1);
  }, [flatOptions]);

  // Keyboard handler when the input is focused.
  const onKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActiveIndex((i) => Math.min(i + 1, flatOptions.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActiveIndex((i) => Math.max(i - 1, 0));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const opt = flatOptions[activeIndex];
      if (opt) {
        onSelect(opt);
        setOpen(false);
        setNeedle('');
        buttonRef.current?.focus();
      }
    } else if (e.key === 'Escape') {
      e.preventDefault();
      setOpen(false);
      buttonRef.current?.focus();
    }
  };

  const triggerLabel = selectedRun
    ? `${selectedRun.sbom_name ?? '—'} · Run #${selectedRun.id} · ${formatDate(
        selectedRun.completed_on,
      )}`
    : 'Choose a run…';

  // Hint banner: user has picked a paired run but no other runs of that
  // SBOM exist in the current option set. Suppressed during search so it
  // doesn't conflate "no runs of this SBOM" with "your search returned
  // nothing", and suppressed while loading to avoid a flash.
  const showSingleRunHint =
    pairedRun != null &&
    pairedRun.sbom_name != null &&
    grouped.primary.length === 0 &&
    debounced === '' &&
    !isLoading &&
    grouped.other.length > 0;

  // Render an option. ``idx`` is the position in the flat list (primary
  // then other) so keyboard navigation lines up with visual order.
  const renderOption = (run: RunSummary, idx: number) => {
    const active = idx === activeIndex;
    const selected = run.id === selectedRunId;
    return (
      <div
        key={run.id}
        id={`${listboxId}-${idx}`}
        role="option"
        aria-selected={selected}
        onMouseEnter={() => setActiveIndex(idx)}
        onClick={() => {
          onSelect(run);
          setOpen(false);
          setNeedle('');
          buttonRef.current?.focus();
        }}
        className={cn(
          'flex cursor-pointer items-center justify-between gap-3 px-3 py-2 text-sm',
          active && 'bg-hcl-light',
          selected && 'text-primary',
        )}
      >
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="truncate font-medium text-hcl-navy">
              {run.sbom_name ?? `Run #${run.id}`}
            </span>
            <span className="font-mono text-[11px] text-hcl-muted">
              #{run.id}
            </span>
          </div>
          <div className="mt-0.5 flex flex-wrap items-center gap-x-1.5 gap-y-0.5 text-[11px] text-hcl-muted">
            {run.project_name && (
              <>
                <span className="truncate">{run.project_name}</span>
                <span aria-hidden>·</span>
              </>
            )}
            <span>{formatDate(run.completed_on)}</span>
            <span aria-hidden>·</span>
            <span className="uppercase">{run.run_status}</span>
          </div>
        </div>
        {selected && (
          <Check className="h-4 w-4 shrink-0 text-primary" aria-hidden />
        )}
      </div>
    );
  };

  // Indices for the "Other SBOMs" group start after the primary group.
  const primaryCount = grouped.primary.length;
  const showPrimarySection = primaryCount > 0 && pairedRun != null;
  const showOtherHeader = showPrimarySection && grouped.other.length > 0;

  return (
    <div ref={wrapRef} className={cn('relative w-full', align === 'right' && 'lg:text-right')}>
      <p className="text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
        {label}
      </p>
      <button
        ref={buttonRef}
        type="button"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={listboxId}
        onClick={() => setOpen((v) => !v)}
        className={cn(
          'mt-1 flex w-full items-center justify-between gap-2 rounded-lg border border-border bg-surface px-3 py-2.5 text-left text-sm text-hcl-navy',
          'hover:border-primary focus-visible:border-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/30',
          !selectedRun && 'text-hcl-muted',
        )}
      >
        <span className="truncate">{triggerLabel}</span>
        <ChevronDown className="h-4 w-4 shrink-0 text-hcl-muted" aria-hidden />
      </button>

      {open && (
        <Surface
          variant="elevated"
          elevation={3}
          className={cn(
            'absolute z-30 mt-1 w-full overflow-hidden p-0',
            align === 'right' && 'lg:right-0',
          )}
        >
          <div className="border-b border-border-subtle p-2">
            <div className="relative">
              <Search
                className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-hcl-muted"
                aria-hidden
              />
              <input
                id={inputId}
                role="combobox"
                aria-controls={listboxId}
                aria-autocomplete="list"
                aria-activedescendant={
                  activeIndex >= 0 ? `${listboxId}-${activeIndex}` : undefined
                }
                autoFocus
                value={needle}
                onChange={(e) => {
                  setNeedle(e.target.value);
                  setActiveIndex(0);
                }}
                onKeyDown={onKeyDown}
                placeholder="Search by SBOM name, project, or run id…"
                className="h-9 w-full rounded-md border border-border bg-surface pl-8 pr-3 text-sm text-hcl-navy placeholder:text-hcl-muted focus-visible:border-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/30"
              />
            </div>
            {pairedProjectId != null && (
              <label className="mt-2 inline-flex cursor-pointer items-center gap-1.5 text-xs text-hcl-muted">
                <input
                  type="checkbox"
                  checked={sameProjectOnly}
                  onChange={(e) => setSameProjectOnly(e.target.checked)}
                  className="h-3.5 w-3.5 rounded border-border accent-hcl-blue"
                />
                Same project as {pairedRunLabel}
              </label>
            )}
          </div>

          {showSingleRunHint && (
            <div
              role="status"
              className="flex items-start gap-2 border-b border-border-subtle bg-hcl-light/50 px-3 py-2 text-[11px] text-hcl-muted"
            >
              <Info className="mt-0.5 h-3.5 w-3.5 shrink-0 text-hcl-blue" aria-hidden />
              <span>
                Only one run of{' '}
                <span className="font-medium text-hcl-navy">
                  {pairedRun?.sbom_name}
                </span>{' '}
                exists. Upload a new version or pick a different SBOM to compare against.
              </span>
            </div>
          )}

          <div
            id={listboxId}
            role="listbox"
            aria-label={`${label} options`}
            className="max-h-72 overflow-y-auto py-1"
          >
            {isLoading && (
              <div className="flex items-center gap-2 px-3 py-3 text-xs text-hcl-muted">
                <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
                Loading runs…
              </div>
            )}
            {!isLoading && flatOptions.length === 0 && (
              <div className="px-3 py-3 text-xs text-hcl-muted">No runs match.</div>
            )}

            {showPrimarySection && (
              <div role="group" aria-labelledby={primaryHeadingId}>
                <div
                  id={primaryHeadingId}
                  className="px-3 pt-2 pb-1 text-[10px] font-semibold uppercase tracking-wider text-hcl-muted"
                >
                  Other runs of {pairedRun?.sbom_name ?? '—'}
                </div>
                {grouped.primary.map((run, i) => renderOption(run, i))}
              </div>
            )}

            {grouped.other.length > 0 && (
              <div role="group" aria-labelledby={otherHeadingId}>
                {showOtherHeader ? (
                  <div
                    id={otherHeadingId}
                    className="mt-1 border-t border-border-subtle px-3 pt-2 pb-1 text-[10px] font-semibold uppercase tracking-wider text-hcl-muted"
                  >
                    Other SBOMs
                  </div>
                ) : (
                  // No visual header needed when this is the only section,
                  // but the role="group" still needs an accessible name so
                  // screen readers can announce it.
                  <span id={otherHeadingId} className="sr-only">
                    Available runs
                  </span>
                )}
                {grouped.other.map((run, i) =>
                  renderOption(run, primaryCount + i),
                )}
              </div>
            )}
          </div>
        </Surface>
      )}
    </div>
  );
}
