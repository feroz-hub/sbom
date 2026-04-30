'use client';

import { useEffect, useId, useMemo, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Check, ChevronDown, Loader2, Search } from 'lucide-react';
import { Surface } from '@/components/ui/Surface';
import { recentRuns, searchRuns } from '@/lib/api';
import { cn, formatDate } from '@/lib/utils';
import type { RunSummary } from '@/types/compare';

interface RunPickerProps {
  label: string;
  selectedRunId: number | null;
  onSelect: (run: RunSummary) => void;
  /**
   * When provided, the dropdown shows a "Same project as Run A" filter chip
   * so picking Run B in the same project takes one fewer click.
   */
  pairedRunProjectId?: number | null;
  align?: 'left' | 'right';
}

/**
 * Typeahead Combobox built from existing primitives — no new shadcn dep.
 *
 * Default open: 20 most recent runs.
 * Type-ahead: 200ms debounced query against /api/runs/search.
 * Keyboard: ↑/↓ navigate, Enter select, Esc close.
 */
export function RunPicker({
  label,
  selectedRunId,
  onSelect,
  pairedRunProjectId,
  align = 'left',
}: RunPickerProps) {
  const inputId = useId();
  const listboxId = useId();
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
  const options = useMemo(() => {
    if (!sameProjectOnly || pairedRunProjectId == null) return baseOptions;
    return baseOptions.filter((r) => r.project_id === pairedRunProjectId);
  }, [baseOptions, sameProjectOnly, pairedRunProjectId]);

  const selectedRun = useMemo(
    () => baseOptions.find((r) => r.id === selectedRunId),
    [baseOptions, selectedRunId],
  );

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

  // Keyboard handler when the input is focused.
  const onKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActiveIndex((i) => Math.min(i + 1, options.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActiveIndex((i) => Math.max(i - 1, 0));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const opt = options[activeIndex];
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
            {pairedRunProjectId != null && (
              <label className="mt-2 inline-flex cursor-pointer items-center gap-1.5 text-xs text-hcl-muted">
                <input
                  type="checkbox"
                  checked={sameProjectOnly}
                  onChange={(e) => setSameProjectOnly(e.target.checked)}
                  className="h-3.5 w-3.5 rounded border-border accent-hcl-blue"
                />
                Same project as Run A
              </label>
            )}
          </div>
          <ul
            id={listboxId}
            role="listbox"
            aria-label={`${label} options`}
            className="max-h-72 overflow-y-auto py-1"
          >
            {isLoading && (
              <li className="flex items-center gap-2 px-3 py-3 text-xs text-hcl-muted">
                <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
                Loading runs…
              </li>
            )}
            {!isLoading && options.length === 0 && (
              <li className="px-3 py-3 text-xs text-hcl-muted">No runs match.</li>
            )}
            {options.map((run, idx) => {
              const active = idx === activeIndex;
              const selected = run.id === selectedRunId;
              return (
                <li
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
                    <div className="mt-0.5 flex items-center gap-1.5 text-[11px] text-hcl-muted">
                      {run.project_name && (
                        <>
                          <span className="truncate">{run.project_name}</span>
                          <span>·</span>
                        </>
                      )}
                      <span>{formatDate(run.completed_on)}</span>
                      <span>·</span>
                      <span className="uppercase">{run.run_status}</span>
                    </div>
                  </div>
                  {selected && (
                    <Check className="h-4 w-4 shrink-0 text-primary" aria-hidden />
                  )}
                </li>
              );
            })}
          </ul>
        </Surface>
      )}
    </div>
  );
}
