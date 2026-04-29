'use client';

import { useEffect, useState } from 'react';
import {
  Bookmark,
  ChevronDown,
  Filter,
  Flame,
  Search,
  Wrench,
  X,
} from 'lucide-react';
import { Button } from '@/components/ui/Button';
import {
  countActiveFilters,
  DEFAULT_FILTERS,
  deletePreset,
  hasActiveFilters,
  loadPresets,
  savePreset,
  type FindingsFilterPreset,
  type FindingsFilterState,
} from '@/lib/findingFilters';
import { cn } from '@/lib/utils';

interface FindingFilterPanelProps {
  filter: FindingsFilterState;
  onChange: (next: FindingsFilterState) => void;
  /** Available source options derived from current findings (NVD, OSV, etc.). */
  sourceOptions: string[];
  /** Server-side severity filter — passes through to the API. */
  onSeverityServerChange?: (severity: string) => void;
  /** Raw count of all findings loaded in memory. */
  totalCount: number;
  /** Filtered count after applying these filters. */
  filteredCount: number;
}

export function FindingFilterPanel({
  filter,
  onChange,
  sourceOptions,
  onSeverityServerChange,
  totalCount,
  filteredCount,
}: FindingFilterPanelProps) {
  const [expanded, setExpanded] = useState(false);
  const [presets, setPresets] = useState<FindingsFilterPreset[]>([]);
  const [showPresets, setShowPresets] = useState(false);
  const [presetName, setPresetName] = useState('');

  useEffect(() => {
    setPresets(loadPresets());
  }, []);

  const activeCount = countActiveFilters(filter);
  const isActive = hasActiveFilters(filter);

  const update = <K extends keyof FindingsFilterState>(key: K, value: FindingsFilterState[K]) => {
    onChange({ ...filter, [key]: value });
  };

  const toggleSource = (src: string) => {
    const next = filter.sources.includes(src)
      ? filter.sources.filter((s) => s !== src)
      : [...filter.sources, src];
    update('sources', next);
  };

  const reset = () => onChange({ ...DEFAULT_FILTERS, severityFilter: filter.severityFilter });

  const handleSavePreset = () => {
    const name = presetName.trim();
    if (!name) return;
    savePreset(name, filter);
    setPresets(loadPresets());
    setPresetName('');
  };

  const handleApplyPreset = (preset: FindingsFilterPreset) => {
    onChange({ ...preset.filter, severityFilter: filter.severityFilter });
    setShowPresets(false);
  };

  const handleDeletePreset = (id: string) => {
    deletePreset(id);
    setPresets(loadPresets());
  };

  return (
    <div className="rounded-xl border border-border bg-surface shadow-card">
      {/* Header — always visible */}
      <div className="flex flex-wrap items-center gap-3 border-b border-border-subtle px-4 py-3">
        {/* Search — always visible */}
        <div className="relative min-w-[14rem] flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-hcl-muted" aria-hidden />
          <input
            type="search"
            value={filter.search}
            onChange={(e) => update('search', e.target.value)}
            placeholder="Search CVE, component, title, CPE, CWE…"
            aria-label="Search findings"
            className="h-10 w-full rounded-lg border border-border bg-surface pl-9 pr-3 text-sm text-hcl-navy placeholder:text-hcl-muted focus-visible:border-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/30"
          />
        </div>

        {/* KEV-only quick toggle */}
        <button
          type="button"
          onClick={() => update('kevOnly', !filter.kevOnly)}
          aria-pressed={filter.kevOnly}
          className={cn(
            'inline-flex h-10 items-center gap-1.5 rounded-lg border px-3 text-xs font-semibold transition-all duration-base ease-spring',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/30',
            filter.kevOnly
              ? 'border-red-300 bg-red-50 text-red-700 shadow-glow-critical dark:border-red-800 dark:bg-red-950/60 dark:text-red-200'
              : 'border-border bg-surface text-hcl-navy hover:-translate-y-px hover:bg-surface-muted',
          )}
        >
          <Flame className="h-3.5 w-3.5" aria-hidden />
          KEV only
        </button>

        {/* Has-fix toggle */}
        <button
          type="button"
          onClick={() => update('hasFixOnly', !filter.hasFixOnly)}
          aria-pressed={filter.hasFixOnly}
          className={cn(
            'inline-flex h-10 items-center gap-1.5 rounded-lg border px-3 text-xs font-semibold transition-all duration-base ease-spring',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/30',
            filter.hasFixOnly
              ? 'border-emerald-300 bg-emerald-50 text-emerald-700 shadow-glow-success dark:border-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-200'
              : 'border-border bg-surface text-hcl-navy hover:-translate-y-px hover:bg-surface-muted',
          )}
        >
          <Wrench className="h-3.5 w-3.5" aria-hidden />
          Fix available
        </button>

        {/* Server severity */}
        {onSeverityServerChange && (
          <select
            value={filter.severityFilter}
            onChange={(e) => onSeverityServerChange(e.target.value)}
            aria-label="Server severity filter"
            className="h-10 rounded-lg border border-border bg-surface px-3 text-xs font-medium text-hcl-navy focus-visible:border-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/30"
          >
            <option value="">All severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="UNKNOWN">Unknown</option>
          </select>
        )}

        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          aria-expanded={expanded}
          className={cn(
            'inline-flex h-10 items-center gap-1.5 rounded-lg border px-3 text-xs font-semibold transition-all duration-base ease-spring',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/30',
            isActive
              ? 'border-primary bg-primary/5 text-primary'
              : 'border-border bg-surface text-hcl-navy hover:-translate-y-px hover:bg-surface-muted',
          )}
        >
          <Filter className="h-3.5 w-3.5" aria-hidden />
          Filters
          {activeCount > 0 && (
            <span className="ml-0.5 inline-flex h-4 min-w-[1rem] items-center justify-center rounded-full bg-primary px-1 font-metric text-[10px] font-bold text-white">
              {activeCount}
            </span>
          )}
          <ChevronDown
            className={cn('h-3.5 w-3.5 transition-transform duration-base', expanded && 'rotate-180')}
            aria-hidden
          />
        </button>

        <button
          type="button"
          onClick={() => setShowPresets((v) => !v)}
          aria-expanded={showPresets}
          aria-haspopup="menu"
          className="inline-flex h-10 items-center gap-1.5 rounded-lg border border-border bg-surface px-3 text-xs font-semibold text-hcl-navy transition-all duration-base ease-spring hover:-translate-y-px hover:bg-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/30"
        >
          <Bookmark className="h-3.5 w-3.5" aria-hidden />
          Presets
          {presets.length > 0 && (
            <span className="font-metric text-[10px] tabular-nums text-hcl-muted">
              {presets.length}
            </span>
          )}
        </button>

        <span className="ml-auto text-xs text-hcl-muted">
          {isActive ? (
            <>
              <span className="font-metric font-semibold text-hcl-navy">{filteredCount}</span> of{' '}
              <span className="font-metric">{totalCount}</span>
            </>
          ) : (
            <>
              <span className="font-metric font-semibold text-hcl-navy">{totalCount}</span>{' '}
              {totalCount === 1 ? 'finding' : 'findings'}
            </>
          )}
        </span>

        {isActive && (
          <Button variant="ghost" size="sm" onClick={reset}>
            Clear
          </Button>
        )}
      </div>

      {/* Presets menu */}
      {showPresets && (
        <div className="border-b border-border-subtle bg-surface-muted/40 px-4 py-3 motion-fade-in">
          <div className="flex flex-wrap items-end gap-2">
            <div className="flex-1 min-w-[16rem]">
              <label className="mb-1 block text-[11px] font-semibold uppercase tracking-wider text-hcl-muted">
                Save current filters as preset
              </label>
              <input
                type="text"
                value={presetName}
                onChange={(e) => setPresetName(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') handleSavePreset();
                }}
                placeholder="e.g. KEV criticals from log4j"
                disabled={!isActive}
                className="h-9 w-full rounded-lg border border-border bg-surface px-3 text-sm text-hcl-navy placeholder:text-hcl-muted disabled:cursor-not-allowed disabled:opacity-60 focus-visible:border-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/30"
              />
            </div>
            <Button
              variant="primary"
              size="sm"
              disabled={!presetName.trim() || !isActive}
              onClick={handleSavePreset}
            >
              Save preset
            </Button>
          </div>
          {!isActive && (
            <p className="mt-2 text-[11px] text-hcl-muted">
              Configure filters first, then save them as a named preset.
            </p>
          )}
          {presets.length > 0 && (
            <ul className="mt-3 flex flex-wrap gap-2">
              {presets.map((p) => (
                <li key={p.id} className="inline-flex items-stretch overflow-hidden rounded-full border border-border bg-surface text-xs">
                  <button
                    type="button"
                    onClick={() => handleApplyPreset(p)}
                    className="px-3 py-1.5 font-medium text-hcl-navy transition-colors hover:bg-primary/5 hover:text-primary focus-visible:outline-none focus-visible:bg-primary/10"
                  >
                    {p.name}
                    <span className="ml-1.5 font-metric text-[10px] text-hcl-muted">
                      {countActiveFilters(p.filter)}
                    </span>
                  </button>
                  <button
                    type="button"
                    onClick={() => handleDeletePreset(p.id)}
                    aria-label={`Delete preset ${p.name}`}
                    className="border-l border-border-subtle px-2 text-hcl-muted transition-colors hover:bg-red-50 hover:text-red-700 focus-visible:outline-none focus-visible:bg-red-50 dark:hover:bg-red-950/40"
                  >
                    <X className="h-3 w-3" aria-hidden />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {/* Expanded filter body */}
      {expanded && (
        <div className="grid grid-cols-1 gap-5 px-4 py-4 motion-fade-in md:grid-cols-2 lg:grid-cols-3">
          {/* CVSS range */}
          <fieldset className="space-y-2">
            <legend className="text-[11px] font-semibold uppercase tracking-wider text-hcl-muted">
              CVSS score range
            </legend>
            <div className="flex items-center gap-2">
              <input
                type="number"
                min={0}
                max={10}
                step={0.1}
                value={filter.cvssMin}
                onChange={(e) => update('cvssMin', clampCvss(e.target.value))}
                aria-label="CVSS minimum"
                className="h-9 w-20 rounded-lg border border-border bg-surface px-2 text-center font-metric text-sm tabular-nums focus-visible:border-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/30"
              />
              <div className="flex-1">
                <DualRange
                  min={filter.cvssMin}
                  max={filter.cvssMax}
                  onChange={(min, max) => onChange({ ...filter, cvssMin: min, cvssMax: max })}
                />
              </div>
              <input
                type="number"
                min={0}
                max={10}
                step={0.1}
                value={filter.cvssMax}
                onChange={(e) => update('cvssMax', clampCvss(e.target.value))}
                aria-label="CVSS maximum"
                className="h-9 w-20 rounded-lg border border-border bg-surface px-2 text-center font-metric text-sm tabular-nums focus-visible:border-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/30"
              />
            </div>
            <p className="text-[11px] text-hcl-muted">
              Show findings with score between {filter.cvssMin.toFixed(1)} and {filter.cvssMax.toFixed(1)}.
            </p>
          </fieldset>

          {/* EPSS percentile */}
          <fieldset className="space-y-2">
            <legend className="text-[11px] font-semibold uppercase tracking-wider text-hcl-muted">
              Min EPSS percentile
            </legend>
            <div className="flex items-center gap-3">
              <input
                type="range"
                min={0}
                max={100}
                step={5}
                value={filter.epssMinPct}
                onChange={(e) => update('epssMinPct', Number(e.target.value))}
                aria-label="EPSS minimum percentile"
                className="flex-1 accent-primary"
              />
              <span className="font-metric w-12 shrink-0 text-right text-sm font-semibold tabular-nums text-hcl-navy">
                {filter.epssMinPct}%
              </span>
            </div>
            <p className="text-[11px] text-hcl-muted">
              Hide findings with EPSS percentile below this threshold.
            </p>
          </fieldset>

          {/* Sources */}
          <fieldset className="space-y-2">
            <legend className="text-[11px] font-semibold uppercase tracking-wider text-hcl-muted">
              Sources
            </legend>
            {sourceOptions.length === 0 ? (
              <p className="text-xs text-hcl-muted">No source data on these findings.</p>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {sourceOptions.map((src) => {
                  const active = filter.sources.includes(src);
                  return (
                    <button
                      key={src}
                      type="button"
                      onClick={() => toggleSource(src)}
                      aria-pressed={active}
                      className={cn(
                        'inline-flex h-7 items-center rounded-full border px-2.5 text-[11px] font-semibold uppercase tracking-wider transition-all duration-base ease-spring',
                        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/30',
                        active
                          ? 'border-primary bg-primary/10 text-primary'
                          : 'border-border bg-surface text-hcl-muted hover:bg-surface-muted hover:text-hcl-navy',
                      )}
                    >
                      {src}
                    </button>
                  );
                })}
              </div>
            )}
          </fieldset>
        </div>
      )}
    </div>
  );
}

function clampCvss(raw: string): number {
  const v = Number(raw);
  if (!Number.isFinite(v)) return 0;
  return Math.max(0, Math.min(10, v));
}

interface DualRangeProps {
  min: number;
  max: number;
  onChange: (min: number, max: number) => void;
}

/** Dual-thumb range slider — two stacked native ranges with a single track. */
function DualRange({ min, max, onChange }: DualRangeProps) {
  const minPct = (min / 10) * 100;
  const maxPct = (max / 10) * 100;
  return (
    <div className="relative h-9">
      <div
        aria-hidden
        className="absolute left-0 right-0 top-1/2 h-1.5 -translate-y-1/2 rounded-full bg-border-subtle"
      />
      <div
        aria-hidden
        className="absolute top-1/2 h-1.5 -translate-y-1/2 rounded-full bg-gradient-to-r from-sky-500 via-amber-500 to-red-600"
        style={{ left: `${minPct}%`, right: `${100 - maxPct}%` }}
      />
      <input
        type="range"
        min={0}
        max={10}
        step={0.5}
        value={min}
        onChange={(e) => {
          const v = Math.min(Number(e.target.value), max);
          onChange(v, max);
        }}
        aria-label="CVSS minimum slider"
        className="pointer-events-none absolute inset-0 h-9 w-full appearance-none bg-transparent [&::-webkit-slider-thumb]:pointer-events-auto [&::-webkit-slider-thumb]:relative [&::-webkit-slider-thumb]:z-10 [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:h-4 [&::-webkit-slider-thumb]:w-4 [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:bg-surface [&::-webkit-slider-thumb]:border-2 [&::-webkit-slider-thumb]:border-primary [&::-webkit-slider-thumb]:shadow-md [&::-moz-range-thumb]:pointer-events-auto [&::-moz-range-thumb]:h-4 [&::-moz-range-thumb]:w-4 [&::-moz-range-thumb]:rounded-full [&::-moz-range-thumb]:bg-surface [&::-moz-range-thumb]:border-2 [&::-moz-range-thumb]:border-primary"
      />
      <input
        type="range"
        min={0}
        max={10}
        step={0.5}
        value={max}
        onChange={(e) => {
          const v = Math.max(Number(e.target.value), min);
          onChange(min, v);
        }}
        aria-label="CVSS maximum slider"
        className="pointer-events-none absolute inset-0 h-9 w-full appearance-none bg-transparent [&::-webkit-slider-thumb]:pointer-events-auto [&::-webkit-slider-thumb]:relative [&::-webkit-slider-thumb]:z-10 [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:h-4 [&::-webkit-slider-thumb]:w-4 [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:bg-surface [&::-webkit-slider-thumb]:border-2 [&::-webkit-slider-thumb]:border-primary [&::-webkit-slider-thumb]:shadow-md [&::-moz-range-thumb]:pointer-events-auto [&::-moz-range-thumb]:h-4 [&::-moz-range-thumb]:w-4 [&::-moz-range-thumb]:rounded-full [&::-moz-range-thumb]:bg-surface [&::-moz-range-thumb]:border-2 [&::-moz-range-thumb]:border-primary"
      />
    </div>
  );
}
