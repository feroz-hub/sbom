'use client';

import { useMemo } from 'react';
import { Search } from 'lucide-react';
import { Surface, SurfaceContent } from '@/components/ui/Surface';
import type { CompareResult, FindingChangeKind, FindingDiffRow } from '@/types/compare';
import { useCompareUrlState } from '@/hooks/useCompareUrlState';
import { FilterChipsAdaptive } from '../FilterChipsAdaptive/FilterChipsAdaptive';
import { FindingsTable } from './FindingsTable';

interface Props {
  result: CompareResult;
}

const KIND_RANK: Record<FindingChangeKind, number> = {
  severity_changed: 0,
  added: 1,
  resolved: 2,
  unchanged: 3,
};

const SEVERITY_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  none: 4,
  unknown: 5,
};

function visibleSeverity(row: FindingDiffRow): string {
  if (row.change_kind === 'resolved') return row.severity_a ?? 'unknown';
  return row.severity_b ?? row.severity_a ?? 'unknown';
}

function applyFilters(
  rows: FindingDiffRow[],
  state: ReturnType<typeof useCompareUrlState>,
): FindingDiffRow[] {
  const q = state.q.trim().toLowerCase();
  return rows
    .filter((row) => {
      if (row.change_kind === 'unchanged') {
        if (!state.showUnchanged) return false;
      } else if (!state.changeKinds.has(row.change_kind)) {
        return false;
      }
      const sev = visibleSeverity(row);
      if (state.severities.size > 0 && !state.severities.has(sev)) return false;
      if (state.kevOnly && !row.kev_current) return false;
      if (state.fixAvailable && !row.fix_available) return false;
      if (q) {
        const haystack = `${row.vuln_id} ${row.component_name} ${row.component_purl ?? ''}`.toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    })
    .sort((a, b) => {
      const ka = KIND_RANK[a.change_kind] ?? 99;
      const kb = KIND_RANK[b.change_kind] ?? 99;
      if (ka !== kb) return ka - kb;
      const sa = SEVERITY_RANK[visibleSeverity(a)] ?? 99;
      const sb = SEVERITY_RANK[visibleSeverity(b)] ?? 99;
      if (sa !== sb) return sa - sb;
      return a.vuln_id.localeCompare(b.vuln_id);
    });
}

export function FindingsTab({ result }: Props) {
  const urlState = useCompareUrlState();
  const visible = useMemo(
    () => applyFilters(result.findings, urlState),
    [result.findings, urlState],
  );

  return (
    <Surface variant="elevated">
      <SurfaceContent className="space-y-3">
        <FilterChipsAdaptive
          rows={result.findings}
          posture={result.posture}
          changeKinds={urlState.changeKinds}
          toggleChangeKind={urlState.toggleChangeKind}
          severities={urlState.severities}
          toggleSeverity={urlState.toggleSeverity}
          kevOnly={urlState.kevOnly}
          setKevOnly={urlState.setKevOnly}
          fixAvailable={urlState.fixAvailable}
          setFixAvailable={urlState.setFixAvailable}
          showUnchanged={urlState.showUnchanged}
          setShowUnchanged={urlState.setShowUnchanged}
          visibleCount={visible.length}
          onClearAll={urlState.clearAllFilters}
        />
        <div className="relative">
          <Search
            className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-hcl-muted"
            aria-hidden
          />
          <input
            type="search"
            value={urlState.q}
            onChange={(e) => urlState.setQ(e.target.value)}
            placeholder="Filter by CVE id, component name, or PURL…"
            aria-label="Filter findings"
            className="h-10 w-full rounded-lg border border-border bg-surface pl-9 pr-3 text-sm text-hcl-navy placeholder:text-hcl-muted focus-visible:border-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/30"
          />
        </div>
        <FindingsTable
          rows={visible}
          scanId={result.run_b.id}
          scanName={result.run_b.sbom_name ?? null}
        />
      </SurfaceContent>
    </Surface>
  );
}
