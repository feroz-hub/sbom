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
              <Th>Severity</Th>
              <Th>Score</Th>
              <Th>Component</Th>
              <Th>Version</Th>
              <Th>CPE</Th>
              <Th>Title / Description</Th>
              <Th>Published</Th>
            </tr>
          </TableHead>
          <TableBody>
            {isLoading ? (
              Array.from({ length: 6 }).map((_, i) => <SkeletonRow key={i} cols={8} />)
            ) : !findings?.length ? (
              <EmptyRow cols={8} message="No findings found for this run." />
            ) : (
              findings.map((f) => (
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
                  <Td className="text-hcl-muted max-w-[220px]">
                    <span title={f.title || f.description || ''}>
                      {truncate(f.title || f.description, 80)}
                    </span>
                  </Td>
                  <Td className="text-hcl-muted whitespace-nowrap">{formatDateShort(f.published_on)}</Td>
                </tr>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
