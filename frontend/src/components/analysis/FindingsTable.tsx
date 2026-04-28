'use client';

import { useMemo, useState } from 'react';
import { ExternalLink } from 'lucide-react';
import { Alert } from '@/components/ui/Alert';
import { Table, TableHead, TableBody, Th, Td, EmptyRow } from '@/components/ui/Table';
import { TableFilterBar, TableSearchInput } from '@/components/ui/TableFilterBar';
import { SeverityBadge } from '@/components/ui/Badge';
import { Select } from '@/components/ui/Select';
import { SkeletonRow } from '@/components/ui/Spinner';
import { matchesMultiField } from '@/lib/tableFilters';
import { formatDateShort, truncate } from '@/lib/utils';
import type { AnalysisFinding } from '@/types';

interface FindingsTableProps {
  findings: AnalysisFinding[] | undefined;
  isLoading: boolean;
  error: Error | null;
  onSeverityChange?: (severity: string) => void;
  severityFilter?: string;
}

/** Parse the JSON aliases string and extract the best CVE alias (if any). */
function extractCveAlias(aliases: string | null | undefined): string | null {
  if (!aliases) return null;
  try {
    const parsed: unknown[] = JSON.parse(aliases);
    if (!Array.isArray(parsed)) return null;
    const cve = parsed.find((a): a is string => typeof a === 'string' && a.startsWith('CVE-'));
    if (cve) return cve;
    return parsed.find((a): a is string => typeof a === 'string' && !a.startsWith('GHSA-')) ?? null;
  } catch {
    return null;
  }
}

/** Generate a canonical URL for a vuln ID (GHSA or CVE). */
function vulnUrl(vulnId: string | null, referenceUrl: string | null): string | null {
  if (referenceUrl) return referenceUrl;
  if (!vulnId) return null;
  if (vulnId.startsWith('GHSA-')) return `https://github.com/advisories/${vulnId}`;
  if (vulnId.startsWith('CVE-')) return `https://nvd.nist.gov/vuln/detail/${vulnId}`;
  return null;
}

/** Map raw source string to short coloured badge. */
function SourceBadge({ source }: { source: string | null }) {
  if (!source) return <span className="text-xs text-hcl-muted">—</span>;

  const parts = source.split(',').map((s) => s.trim());

  const colorMap: Record<string, string> = {
    NVD: 'border-indigo-200 bg-indigo-50 text-indigo-700 dark:border-indigo-800 dark:bg-indigo-950/50 dark:text-indigo-200',
    OSV: 'border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-200',
    GITHUB: 'border-purple-200 bg-purple-50 text-purple-700 dark:border-purple-800 dark:bg-purple-950/50 dark:text-purple-200',
    VULNDB: 'border-cyan-200 bg-cyan-50 text-cyan-800 dark:border-cyan-800 dark:bg-cyan-950/50 dark:text-cyan-200',
  };

  return (
    <div className="flex flex-wrap gap-1">
      {parts.map((s) => (
        <span
          key={s}
          className={`inline-block rounded border px-1.5 py-0.5 text-[10px] font-semibold ${colorMap[s] ?? 'border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-300'}`}
        >
          {s}
        </span>
      ))}
    </div>
  );
}

export function FindingsTable({
  findings,
  isLoading,
  error,
  onSeverityChange,
  severityFilter = '',
}: FindingsTableProps) {
  const [search, setSearch] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');

  const sourceOptions = useMemo(() => {
    const set = new Set<string>();
    findings?.forEach((f) => {
      if (f.source?.trim()) {
        f.source.split(',').forEach((s) => set.add(s.trim()));
      }
    });
    return Array.from(set).sort((a, b) => a.localeCompare(b));
  }, [findings]);

  const filteredFindings = useMemo(() => {
    if (!findings?.length) return [];
    let rows = findings;
    if (sourceFilter) {
      rows = rows.filter((f) =>
        (f.source ?? '')
          .toUpperCase()
          .includes(sourceFilter.toUpperCase()),
      );
    }
    if (search.trim()) {
      rows = rows.filter((f) => {
        const cveAlias = extractCveAlias(f.aliases);
        const displayTitle =
          f.description && f.description !== f.vuln_id
            ? f.description
            : f.title && f.title !== f.vuln_id
              ? f.title
              : f.description || f.title;
        return matchesMultiField(search, [
          f.vuln_id,
          cveAlias,
          f.severity,
          f.component_name,
          f.component_version,
          f.cpe,
          f.source,
          f.title,
          f.description,
          displayTitle,
        ]);
      });
    }
    return rows;
  }, [findings, search, sourceFilter]);

  const filtersActive = Boolean(search.trim() || sourceFilter);
  const clearFilters = () => {
    setSearch('');
    setSourceFilter('');
  };

  if (error) {
    return (
      <Alert variant="error" title="Could not load findings">
        {error.message}
      </Alert>
    );
  }

  const total = findings?.length ?? 0;
  const shown = filteredFindings.length;

  return (
    <div className="space-y-3">
      <div className="overflow-hidden rounded-xl border border-hcl-border bg-surface shadow-card">
        {!isLoading && total > 0 ? (
          <TableFilterBar
            onClear={clearFilters}
            clearDisabled={!filtersActive}
            resultHint={
              filtersActive ? `Showing ${shown} of ${total}` : `${total} finding${total === 1 ? '' : 's'}`
            }
          >
            <TableSearchInput
              id="findings-search"
              value={search}
              onChange={setSearch}
              placeholder="CVE, component, title, CPE, source…"
              label="Search findings"
            />
            {onSeverityChange ? (
              <div className="w-full min-w-[10rem] sm:w-44">
                <Select
                  label="Severity (server)"
                  value={severityFilter}
                  onChange={(e) => onSeverityChange(e.target.value)}
                  className="w-full"
                >
                  <option value="">All severities</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                  <option value="UNKNOWN">Unknown</option>
                </Select>
              </div>
            ) : null}
            <div className="w-full min-w-[10rem] sm:w-44">
              <Select
                label="Source"
                value={sourceFilter}
                onChange={(e) => setSourceFilter(e.target.value)}
                className="w-full"
              >
                <option value="">All sources</option>
                {sourceOptions.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </Select>
            </div>
          </TableFilterBar>
        ) : null}

        <Table striped>
          <TableHead>
            <tr>
              <Th>Vuln ID</Th>
              <Th>CVE / Alias</Th>
              <Th>Severity</Th>
              <Th>Score</Th>
              <Th>Component</Th>
              <Th>Version</Th>
              <Th>CPE</Th>
              <Th>Source</Th>
              <Th>Title / Description</Th>
              <Th>Published</Th>
            </tr>
          </TableHead>
          <TableBody>
            {isLoading ? (
              Array.from({ length: 6 }).map((_, i) => <SkeletonRow key={i} cols={10} />)
            ) : !findings?.length ? (
              <EmptyRow cols={10} message="No findings found for this run." />
            ) : !filteredFindings.length ? (
              <EmptyRow
                cols={10}
                message="No findings match your search or source filter. Clear filters to see all loaded rows."
              />
            ) : (
              filteredFindings.map((f) => {
                const cveAlias = extractCveAlias(f.aliases) ?? (f.vuln_id?.startsWith('CVE-') ? f.vuln_id : null);
                const displayTitle =
                  f.description && f.description !== f.vuln_id
                    ? f.description
                    : f.title && f.title !== f.vuln_id
                      ? f.title
                      : f.description || f.title;

                return (
                  <tr key={f.id} className="transition-colors hover:bg-hcl-light/40">
                    <Td>
                      {(() => {
                        const url = vulnUrl(f.vuln_id, f.reference_url);
                        return url ? (
                          <a
                            href={url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 font-mono text-xs text-hcl-blue hover:underline"
                          >
                            {f.vuln_id || '—'}
                            <ExternalLink className="h-3 w-3" />
                          </a>
                        ) : (
                          <span className="font-mono text-xs text-foreground/90">{f.vuln_id || '—'}</span>
                        );
                      })()}
                    </Td>
                    <Td>
                      {cveAlias ? (
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${cveAlias}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 font-mono text-xs text-hcl-blue hover:underline"
                        >
                          {cveAlias}
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      ) : (
                        <span className="text-xs text-hcl-muted">—</span>
                      )}
                    </Td>
                    <Td>
                      <SeverityBadge severity={f.severity ?? 'UNKNOWN'} />
                    </Td>
                    <Td className="text-foreground/90">
                      {f.score != null ? f.score.toFixed(1) : '—'}
                    </Td>
                    <Td className="font-medium text-hcl-navy">{f.component_name || '—'}</Td>
                    <Td className="font-mono text-xs text-hcl-muted">{f.component_version || '—'}</Td>
                    <Td className="max-w-[160px] truncate font-mono text-xs text-hcl-muted">
                      <span title={f.cpe || ''}>{f.cpe || '—'}</span>
                    </Td>
                    <Td>
                      <SourceBadge source={f.source} />
                    </Td>
                    <Td className="max-w-[220px] text-hcl-muted">
                      <span title={displayTitle || ''}>{truncate(displayTitle, 80)}</span>
                    </Td>
                    <Td className="whitespace-nowrap text-hcl-muted">{formatDateShort(f.published_on)}</Td>
                  </tr>
                );
              })
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
