'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import { ArrowLeft, Download } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Alert } from '@/components/ui/Alert';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { StatusBadge, SeverityBadge } from '@/components/ui/Badge';
import { FindingsTable } from '@/components/analysis/FindingsTable';
import { PageSpinner } from '@/components/ui/Spinner';
import { getRun, getAllRunFindings, downloadPdfReport, exportRunCsv, exportRunSarif } from '@/lib/api';
import { runStatusDescription } from '@/lib/analysisRunStatusLabels';
import { formatDate, formatDuration, downloadBlob } from '@/lib/utils';
import { useToast } from '@/hooks/useToast';

interface AnalysisDetailPageProps {
  params: { id: string };
}

export default function AnalysisDetailPage({ params }: AnalysisDetailPageProps) {
  const id = Number(params.id);
  const router = useRouter();
  const { showToast } = useToast();
  const [severityFilter, setSeverityFilter] = useState('');
  const [downloading, setDownloading] = useState(false);

  const { data: run, isLoading: runLoading, error: runError } = useQuery({
    queryKey: ['run', id],
    queryFn: ({ signal }) => getRun(id, signal),
    enabled: !isNaN(id),
  });

  const { data: findingsData, isLoading: findingsLoading, error: findingsError } = useQuery({
    queryKey: ['findings', id, severityFilter],
    queryFn: ({ signal }) =>
      getAllRunFindings(id, { severity: severityFilter || undefined }, signal),
    enabled: !isNaN(id),
  });
  const findings = findingsData?.findings;
  const findingsTotalCount = findingsData?.totalCount;

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
        <TopBar
          title="Analysis Detail"
          breadcrumbs={[{ label: 'Analysis Runs', href: '/analysis' }]}
        />
        <div className="p-6">
          <PageSpinner />
        </div>
      </div>
    );
  }

  if (runError || !run) {
    return (
      <div className="flex flex-col flex-1">
        <TopBar
          title="Analysis Detail"
          breadcrumbs={[{ label: 'Analysis Runs', href: '/analysis' }]}
        />
        <div className="p-6">
          <Alert variant="error" title={runError ? 'Could not load run' : 'Not found'}>
            {runError ? runError.message : 'This analysis run does not exist or was removed.'}
          </Alert>
        </div>
      </div>
    );
  }

  const severityBreakdown = [
    {
      label: 'Critical',
      count: run.critical_count,
      color:
        'border-red-200 bg-red-50 text-red-700 dark:border-red-800 dark:bg-red-950/40 dark:text-red-200',
    },
    {
      label: 'High',
      count: run.high_count,
      color:
        'border-orange-200 bg-orange-50 text-orange-700 dark:border-orange-800 dark:bg-orange-950/40 dark:text-orange-200',
    },
    {
      label: 'Medium',
      count: run.medium_count,
      color:
        'border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-200',
    },
    { label: 'Low', count: run.low_count, color: 'border-hcl-border bg-hcl-light text-hcl-blue' },
    {
      label: 'Unknown',
      count: run.unknown_count,
      color:
        'border-slate-200 bg-slate-100 text-slate-600 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-300',
    },
  ];

  return (
    <div className="flex flex-col flex-1">
      <TopBar
        title={`Analysis Run #${run.id}`}
        breadcrumbs={[{ label: 'Analysis Runs', href: '/analysis' }]}
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
            <p className="mb-4 text-xs leading-relaxed text-hcl-muted">
              Outcome:{' '}
              <span className="text-foreground">{runStatusDescription(run.run_status)}</span>
            </p>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
              {[
                { label: 'Outcome', value: <StatusBadge status={run.run_status} /> },
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
              <div className="mt-4">
                <Alert variant="error" title="Run error">
                  {run.error_message}
                </Alert>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Findings */}
        <Card>
          <CardHeader>
            <CardTitle>
              Findings
              {findingsData != null && (
                <span className="ml-2 text-sm font-normal text-hcl-muted">
                  ({findingsTotalCount?.toLocaleString() ?? findings?.length ?? 0})
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
