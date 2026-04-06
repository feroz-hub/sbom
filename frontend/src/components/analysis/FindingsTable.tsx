'use client';

import { ExternalLink } from 'lucide-react';
import { Table, TableHead, TableBody, Th, Td, EmptyRow } from '@/components/ui/Table';
import { SeverityBadge } from '@/components/ui/Badge';
import { Select } from '@/components/ui/Select';
import { SkeletonRow } from '@/components/ui/Spinner';
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
    const parsed: string[] = JSON.parse(aliases);
    // Prefer CVE, then fall back to first non-GHSA alias
    const cve = parsed.find((a) => a.startsWith('CVE-'));
    if (cve) return cve;
    return parsed.find((a) => !a.startsWith('GHSA-')) ?? null;
  } catch {
    return null;
  }
}

/** Map raw source string to short coloured badge. */
function SourceBadge({ source }: { source: string | null }) {
  if (!source) return <span className="text-xs text-slate-400">—</span>;

  const parts = source.split(',').map((s) => s.trim());

  const colorMap: Record<string, string> = {
    NVD: 'bg-indigo-50 text-indigo-700 border-indigo-200',
    OSV: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    GITHUB: 'bg-purple-50 text-purple-700 border-purple-200',
  };

  return (
    <div className="flex flex-wrap gap-1">
      {parts.map((s) => (
        <span
          key={s}
          className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-semibold border ${colorMap[s] ?? 'bg-slate-50 text-slate-600 border-slate-200'}`}
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
  if (error) {
    return (
      <div className="rounded-lg bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
        Failed to load findings: {error.message}
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {onSeverityChange && (
        <div className="flex items-center gap-3">
          <Select
            value={severityFilter}
            onChange={(e) => onSeverityChange(e.target.value)}
            className="w-44"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="UNKNOWN">Unknown</option>
          </Select>
          {findings && (
            <span className="text-sm text-hcl-muted">
              {findings.length} finding{findings.length !== 1 ? 's' : ''}
            </span>
          )}
        </div>
      )}

      <div className="bg-white rounded-xl border border-hcl-border shadow-card overflow-hidden">
        <Table>
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
            ) : (
              findings.map((f) => {
                const cveAlias = extractCveAlias(f.aliases);
                // For title/description: prefer actual description text over vuln_id echo
                const displayTitle =
                  f.description && f.description !== f.vuln_id
                    ? f.description
                    : f.title && f.title !== f.vuln_id
                      ? f.title
                      : f.description || f.title;

                return (
                  <tr key={f.id} className="hover:bg-hcl-light/40 transition-colors">
                    <Td>
                      {f.reference_url ? (
                        <a
                          href={f.reference_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 text-hcl-blue font-mono text-xs hover:underline"
                        >
                          {f.vuln_id || '—'}
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      ) : (
                        <span className="font-mono text-xs text-slate-700">{f.vuln_id || '—'}</span>
                      )}
                    </Td>
                    <Td>
                      {cveAlias ? (
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${cveAlias}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 text-hcl-blue font-mono text-xs hover:underline"
                        >
                          {cveAlias}
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      ) : (
                        <span className="text-xs text-slate-400">—</span>
                      )}
                    </Td>
                    <Td>
                      <SeverityBadge severity={f.severity ?? 'UNKNOWN'} />
                    </Td>
                    <Td className="text-slate-700">
                      {f.score != null ? f.score.toFixed(1) : '—'}
                    </Td>
                    <Td className="font-medium text-hcl-navy">{f.component_name || '—'}</Td>
                    <Td className="font-mono text-xs text-hcl-muted">{f.component_version || '—'}</Td>
                    <Td className="font-mono text-xs text-hcl-muted max-w-[160px] truncate">
                      <span title={f.cpe || ''}>{f.cpe || '—'}</span>
                    </Td>
                    <Td>
                      <SourceBadge source={f.source} />
                    </Td>
                    <Td className="text-hcl-muted max-w-[220px]">
                      <span title={displayTitle || ''}>
                        {truncate(displayTitle, 80)}
                      </span>
                    </Td>
                    <Td className="text-hcl-muted whitespace-nowrap">{formatDateShort(f.published_on)}</Td>
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
