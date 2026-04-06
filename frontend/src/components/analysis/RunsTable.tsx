'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Eye, Download } from 'lucide-react';
import { Table, TableHead, TableBody, Th, Td, EmptyRow } from '@/components/ui/Table';
import { StatusBadge, SeverityBadge } from '@/components/ui/Badge';
import { SkeletonRow } from '@/components/ui/Spinner';
import { downloadPdfReport } from '@/lib/api';
import { formatDate, formatDuration, downloadBlob } from '@/lib/utils';
import { useToast } from '@/hooks/useToast';
import type { AnalysisRun } from '@/types';

interface RunsTableProps {
  runs: AnalysisRun[] | undefined;
  isLoading: boolean;
  error: Error | null;
}

export function RunsTable({ runs, isLoading, error }: RunsTableProps) {
  const router = useRouter();
  const { showToast } = useToast();
  const [downloadingId, setDownloadingId] = useState<number | null>(null);

  const handleDownloadPdf = async (run: AnalysisRun) => {
    setDownloadingId(run.id);
    try {
      const blob = await downloadPdfReport({
        runId: run.id,
        title: `Analysis Report - Run #${run.id}`,
        filename: `sbom-analysis-run-${run.id}.pdf`,
      });
      downloadBlob(blob, `sbom-analysis-run-${run.id}.pdf`);
      showToast('PDF report downloaded', 'success');
    } catch (err) {
      showToast(`Failed to download PDF: ${(err as Error).message}`, 'error');
    } finally {
      setDownloadingId(null);
    }
  };

  if (error) {
    return (
      <div className="rounded-lg bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
        Failed to load analysis runs: {error.message}
      </div>
    );
  }

  return (
    <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
      <Table>
        <TableHead>
          <tr>
            <Th>Run ID</Th>
            <Th>SBOM</Th>
            <Th>Status</Th>
            <Th>Source</Th>
            <Th>Components</Th>
            <Th>Findings</Th>
            <Th>Duration</Th>
            <Th>Started On</Th>
            <Th className="text-right">Actions</Th>
          </tr>
        </TableHead>
        <TableBody>
          {isLoading ? (
            Array.from({ length: 5 }).map((_, i) => <SkeletonRow key={i} cols={9} />)
          ) : !runs?.length ? (
            <EmptyRow cols={9} message="No analysis runs found. Run an analysis from an SBOM detail page." />
          ) : (
            runs.map((run) => (
              <tr
                key={run.id}
                className="hover:bg-gray-50 transition-colors cursor-pointer"
                onClick={() => router.push(`/analysis/${run.id}`)}
              >
                <Td className="font-mono text-xs text-gray-400">#{run.id}</Td>
                <Td className="font-medium text-gray-900 max-w-[160px] truncate">
                  {run.sbom_name || (run.sbom_id ? `SBOM #${run.sbom_id}` : '—')}
                </Td>
                <Td onClick={(e) => e.stopPropagation()}>
                  <StatusBadge status={run.run_status} />
                </Td>
                <Td className="text-gray-500 text-xs">{run.source || '—'}</Td>
                <Td className="text-gray-700">{run.total_components ?? '—'}</Td>
                <Td onClick={(e) => e.stopPropagation()}>
                  <div className="flex items-center gap-1 flex-wrap">
                    {run.critical_count != null && run.critical_count > 0 && (
                      <span className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-red-100 text-red-700">
                        C:{run.critical_count}
                      </span>
                    )}
                    {run.high_count != null && run.high_count > 0 && (
                      <span className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-orange-100 text-orange-700">
                        H:{run.high_count}
                      </span>
                    )}
                    {run.medium_count != null && run.medium_count > 0 && (
                      <span className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-yellow-100 text-yellow-700">
                        M:{run.medium_count}
                      </span>
                    )}
                    {run.low_count != null && run.low_count > 0 && (
                      <span className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-700">
                        L:{run.low_count}
                      </span>
                    )}
                    {run.total_findings === 0 && (
                      <span className="text-xs text-gray-400">None</span>
                    )}
                    {run.total_findings == null && (
                      <span className="text-xs text-gray-400">—</span>
                    )}
                  </div>
                </Td>
                <Td className="text-gray-500">{formatDuration(run.duration_seconds)}</Td>
                <Td className="text-gray-500 whitespace-nowrap">{formatDate(run.started_on)}</Td>
                <Td className="text-right" onClick={(e) => e.stopPropagation()}>
                  <div className="flex items-center justify-end gap-2">
                    <button
                      onClick={() => router.push(`/analysis/${run.id}`)}
                      className="p-1.5 text-gray-400 hover:text-primary hover:bg-blue-50 rounded-lg transition-colors"
                      aria-label="View run"
                    >
                      <Eye className="h-4 w-4" />
                    </button>
                    <button
                      onClick={() => handleDownloadPdf(run)}
                      disabled={downloadingId === run.id}
                      className="p-1.5 text-gray-400 hover:text-green-600 hover:bg-green-50 rounded-lg transition-colors disabled:opacity-50"
                      aria-label="Download PDF"
                    >
                      <Download className="h-4 w-4" />
                    </button>
                  </div>
                </Td>
              </tr>
            ))
          )}
        </TableBody>
      </Table>
    </div>
  );
}
