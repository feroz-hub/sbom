'use client';

import { useMemo, useState } from 'react';
import { ArrowDown, ArrowUp, Search, ShieldAlert } from 'lucide-react';
import { Surface, SurfaceContent } from '@/components/ui/Surface';
import { cn } from '@/lib/utils';
import type { CompareResult, ComponentChangeKind, ComponentDiffRow } from '@/types/compare';
import { ComponentChangeKindChip } from '../FindingsTab/ChangeKindChip';

interface Props {
  result: CompareResult;
}

const COMPONENT_KIND_RANK: Record<ComponentChangeKind, number> = {
  hash_changed: 0,
  license_changed: 1,
  added: 2,
  removed: 3,
  version_bumped: 4,
  unchanged: 5,
};

function applyFilters(
  rows: ComponentDiffRow[],
  needle: string,
  showUnchanged: boolean,
): ComponentDiffRow[] {
  const q = needle.trim().toLowerCase();
  return rows
    .filter((c) => {
      if (c.change_kind === 'unchanged' && !showUnchanged) return false;
      if (q) {
        const haystack = `${c.name} ${c.ecosystem} ${c.purl ?? ''}`.toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    })
    .sort((a, b) => {
      const ra = COMPONENT_KIND_RANK[a.change_kind] ?? 99;
      const rb = COMPONENT_KIND_RANK[b.change_kind] ?? 99;
      if (ra !== rb) return ra - rb;
      return a.name.localeCompare(b.name);
    });
}

function versionTransition(c: ComponentDiffRow): string {
  if (c.change_kind === 'added') return c.version_b ?? '—';
  if (c.change_kind === 'removed') return c.version_a ?? '—';
  if (c.version_a === c.version_b) return c.version_b ?? '—';
  return `${c.version_a ?? '—'} → ${c.version_b ?? '—'}`;
}

export function ComponentsTab({ result }: Props) {
  const [needle, setNeedle] = useState('');
  const [showUnchanged, setShowUnchanged] = useState(false);
  const visible = useMemo(
    () => applyFilters(result.components, needle, showUnchanged),
    [result.components, needle, showUnchanged],
  );

  const hasHashAlerts = result.components.some((c) => c.change_kind === 'hash_changed');

  return (
    <Surface variant="elevated">
      <SurfaceContent className="space-y-4">
        {hasHashAlerts && (
          <div className="flex items-start gap-3 rounded-lg border border-red-300 bg-red-50 px-3 py-2.5 text-sm dark:border-red-700 dark:bg-red-950/40">
            <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-red-700 dark:text-red-200" aria-hidden />
            <div className="text-red-900 dark:text-red-100">
              <strong>Supply-chain alert:</strong> one or more components have the same
              version but different content hashes. This is uncommon and may indicate
              tampering or a compromised registry. Inspect carefully.
            </div>
          </div>
        )}

        <div className="flex flex-wrap items-center gap-2">
          <div className="relative flex-1">
            <Search
              className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-hcl-muted"
              aria-hidden
            />
            <input
              type="search"
              value={needle}
              onChange={(e) => setNeedle(e.target.value)}
              placeholder="Filter by component name, ecosystem, or PURL…"
              aria-label="Filter components"
              className="h-10 w-full rounded-lg border border-border bg-surface pl-9 pr-3 text-sm text-hcl-navy placeholder:text-hcl-muted focus-visible:border-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/30"
            />
          </div>
          <label className="inline-flex cursor-pointer items-center gap-2 text-xs text-hcl-muted">
            <input
              type="checkbox"
              checked={showUnchanged}
              onChange={(e) => setShowUnchanged(e.target.checked)}
              className="h-4 w-4 rounded border-border accent-hcl-blue"
            />
            Show unchanged
          </label>
        </div>

        {visible.length === 0 ? (
          <div className="rounded-lg border border-dashed border-border-subtle bg-surface-muted/40 px-6 py-10 text-center text-sm text-hcl-muted">
            No components match the active filters.
          </div>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border-subtle">
            <table className="w-full table-auto text-sm">
              <thead className="bg-surface-muted text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
                <tr>
                  <th className="px-3 py-2 text-left">Change</th>
                  <th className="px-3 py-2 text-left">Component</th>
                  <th className="px-3 py-2 text-left">Ecosystem</th>
                  <th className="px-3 py-2 text-left">Version</th>
                  <th className="px-3 py-2 text-right">Linked findings</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((row) => {
                  const direction =
                    row.change_kind === 'version_bumped'
                      ? (row.version_b ?? '') > (row.version_a ?? '')
                        ? 'up'
                        : 'down'
                      : null;
                  const Arrow = direction === 'up' ? ArrowUp : ArrowDown;
                  return (
                    <tr
                      key={`${row.name}|${row.ecosystem}|${row.version_a ?? ''}|${row.version_b ?? ''}`}
                      className={cn(
                        'border-b border-border-subtle transition-colors hover:bg-hcl-light/40',
                        row.change_kind === 'removed' && 'opacity-80',
                      )}
                    >
                      <td className="px-3 py-2.5 align-top">
                        <ComponentChangeKindChip kind={row.change_kind} />
                      </td>
                      <td className="px-3 py-2.5 align-top">
                        <div className="text-sm font-medium text-hcl-navy">
                          {row.name}
                        </div>
                        {row.purl && (
                          <div className="font-mono text-[10px] text-hcl-muted truncate max-w-md">
                            {row.purl}
                          </div>
                        )}
                      </td>
                      <td className="px-3 py-2.5 align-top text-xs text-hcl-muted">
                        {row.ecosystem}
                      </td>
                      <td className="px-3 py-2.5 align-top">
                        <div className="inline-flex items-center gap-1 font-mono text-xs tabular-nums text-hcl-navy">
                          {direction && (
                            <Arrow
                              className={cn(
                                'h-3 w-3',
                                direction === 'up'
                                  ? 'text-emerald-600'
                                  : 'text-amber-600',
                              )}
                              aria-hidden
                            />
                          )}
                          {versionTransition(row)}
                        </div>
                      </td>
                      <td className="px-3 py-2.5 align-top text-right text-xs">
                        {row.findings_resolved > 0 && (
                          <span className="mr-1.5 rounded-full border border-emerald-300 bg-emerald-50 px-1.5 py-0.5 text-[10px] font-semibold text-emerald-900">
                            −{row.findings_resolved} resolved
                          </span>
                        )}
                        {row.findings_added > 0 && (
                          <span className="rounded-full border border-red-300 bg-red-50 px-1.5 py-0.5 text-[10px] font-semibold text-red-900">
                            +{row.findings_added} new
                          </span>
                        )}
                        {row.findings_resolved === 0 && row.findings_added === 0 && (
                          <span className="text-hcl-muted">—</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </SurfaceContent>
    </Surface>
  );
}
