'use client';

import { use, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import { ArrowLeft, Download } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { StatusBadge, SeverityBadge } from '@/components/ui/Badge';
import { FindingsTable } from '@/components/analysis/FindingsTable';
import { PageSpinner } from '@/components/ui/Spinner';
import { getRun, getRunFindings, downloadPdfReport, exportRunCsv, exportRunSarif } from '@/lib/api';
import { formatDate, formatDuration, downloadBlob } from '@/lib/utils';
import { useToast } from '@/hooks/useToast';

interface AnalysisDetailPageProps {
  params: Promise<{ id: string }>;
}

export default function AnalysisDetailPage({ params }: AnalysisDetailPageProps) {
  const { id: idParam } = use(params);
  const id = Number(idParam);
  const router = useRouter();
  const { showToast } = useToast();
  const [severityFilter, setSeverityFilter] = useState('');
  const [downloading, setDownloading] = useState(false);

  const { data: run, isLoading: runLoading, error: runError } = useQuery({
    queryKey: ['run', id],
    queryFn: ({ signal }) => getRun(id, signal),
    enabled: !isNaN(id),
  });

  const { data: findings, isLoading: findingsLoading, error: findingsError } = useQuery({
    queryKey: ['findings', id, severityFilter],
    queryFn: ({ signal }) =>
      getRunFindings(id, { severity: severityFilter || undefined, page: 1, page_size: 200 }, signal),
    enabled: !isNaN(id),
  });

  const handleDownloadPdf = async () => {
    if (!run) return;
    setDownloading(true);
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
      setDownloading(false);
    }
  };

  const handleDownloadCsv = async () => {
    if (!run) return;
    try {
      const { blob, filename } = await exportRunCsv(run.id);
      downloadBlob(blob, filename);
      showToast('CSV exported', 'success');
    } catch (err) {
      showToast(`Failed to export CSV: ${(err as Error).message}`, 'error');
    }
  };

  const handleDownloadSarif = async () => {
    if (!run) return;
    try {
      const { blob, filename } = await exportRunSarif(run.id);
      downloadBlob(blob, filename);
      showToast('SARIF exported', 'success');
    } catch (err) {
      showToast(`Failed to export SARIF: ${(err as Error).message}`, 'error');
    }
  };

  if (runLoading) {
    return (
      <div className="flex flex-col flex-1">
        <TopBar title="Analysis Detail" />
        <div className="p-6">
          <PageSpinner />
        </div>
      </div>
    );
  }

  if (runError || !run) {
    return (
      <div className="flex flex-col flex-1">
        <TopBar title="Analysis Detail" />
        <div className="p-6">
          <div className="rounded-lg bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
            {runError ? `Failed to load run: ${runError.message}` : 'Run not found'}
          </div>
        </div>
      </div>
    );
  }

  const severityBreakdown = [
    { label: 'Critical', count: run.critical_count, color: 'bg-red-50 text-red-700 border-red-200' },
    { label: 'High', count: run.high_count, color: 'bg-orange-50 text-orange-700 border-orange-200' },
    { label: 'Medium', count: run.medium_count, color: 'bg-amber-50 text-amber-700 border-amber-200' },
    { label: 'Low', count: run.low_count, color: 'bg-hcl-light text-hcl-blue border-hcl-border' },
    { label: 'Unknown', count: run.unknown_count, color: 'bg-slate-100 text-slate-600 border-slate-200' },
  ];

  return (
    <div className="flex flex-col flex-1">
      <TopBar
        title={`Analysis Run #${run.id}`}
        action={
          <div className="flex items-center gap-2">
            <Button variant="secondary" size="sm" onClick={handleDownloadCsv}>
              <Download className="h-4 w-4" />
              CSV
            </Button>
            <Button variant="secondary" size="sm" onClick={handleDownloadSarif}>
              <Download className="h-4 w-4" />
              SARIF
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={handleDownloadPdf}
              loading={downloading}
            >
              <Download className="h-4 w-4" />
              PDF
            </Button>
          </div>
        }
      />
      <div className="p-6 space-y-6">
        {/* Back */}
        <button
          onClick={() => router.back()}
          className="flex items-center gap-2 text-sm text-hcl-muted hover:text-hcl-navy transition-colors"
        >
          <ArrowLeft className="h-4 w-4" /> Back to Analysis Runs
        </button>

        {/* Summary Card */}
        <Card>
          <CardHeader>
            <CardTitle>Run Summary</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
              {[
                { label: 'Status', value: <StatusBadge status={run.run_status} /> },
                { label: 'Source', value: run.source || '—' },
                { label: 'Duration', value: formatDuration(run.duration_ms) },
                { label: 'Total Components', value: run.total_components?.toLocaleString() ?? '—' },
                { label: 'Total Findings', value: run.total_findings?.toLocaleString() ?? '—' },
                { label: 'SBOM', value: run.sbom_name || (run.sbom_id ? `#${run.sbom_id}` : '—') },
                { label: 'Started On', value: formatDate(run.started_on) },
                { label: 'Completed On', value: formatDate(run.completed_on) },
              ].map(({ label, value }) => (
                <div key={label}>
                  <dt className="text-xs font-medium text-hcl-muted uppercase tracking-wide">{label}</dt>
                  <dd className="mt-1 text-sm font-medium text-hcl-navy">{value}</dd>
                </div>
              ))}
            </div>

            {/* Severity breakdown */}
            <div>
              <p className="text-xs font-medium text-hcl-muted uppercase tracking-wide mb-2">
                Findings Breakdown
              </p>
              <div className="flex flex-wrap gap-2">
                {severityBreakdown.map(({ label, count, color }) =>
                  count != null ? (
                    <span
                      key={label}
                      className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium border ${color}`}
                    >
                      {label}: {count}
                    </span>
                  ) : null
                )}
              </div>
            </div>

            {run.error_message && (
              <div className="mt-4 rounded-lg bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
                <strong>Error:</strong> {run.error_message}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Findings */}
        <Card>
          <CardHeader>
            <CardTitle>
              Findings
              {findings && (
                <span className="ml-2 text-sm font-normal text-hcl-muted">
                  ({findings.length})
                </span>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0 pb-4 px-4">
            <FindingsTable
              findings={findings}
              isLoading={findingsLoading}
              error={findingsError}
              onSeverityChange={setSeverityFilter}
              severityFilter={severityFilter}
            />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
