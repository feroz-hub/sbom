'use client';

import { use, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import {
  ArrowLeft,
  FileBarChart,
  FileCode2,
  FileSpreadsheet,
} from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Alert } from '@/components/ui/Alert';
import { ExportMenu } from '@/components/ui/ExportMenu';
import { Surface, SurfaceContent, SurfaceHeader } from '@/components/ui/Surface';
import { Motion } from '@/components/ui/Motion';
import { RunBatchProgress } from '@/components/ai-fixes/RunBatchProgress';
import { FindingsTable } from '@/components/analysis/FindingsTable';
import { RunDetailHero } from '@/components/analysis/RunDetailHero';
import { PageSpinner, SkeletonTable } from '@/components/ui/Spinner';
import { DEFAULT_FILTERS, type FindingsFilterState } from '@/lib/findingFilters';
import {
  getAnalysisConfig,
  getRun,
  getAllEnrichedRunFindings,
  downloadPdfReport,
  exportRunCsv,
  exportRunSarif,
} from '@/lib/api';
import { runStatusDescription } from '@/lib/analysisRunStatusLabels';
import { downloadBlob } from '@/lib/utils';
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
  // Lifted filter state — drives both the findings table and the
  // scope-aware AI fix CTA. The findings table operates in controlled
  // mode; the CTA reads ``filter`` directly to compose its scope.
  const [filter, setFilter] = useState<FindingsFilterState>(() => ({
    ...DEFAULT_FILTERS,
  }));
  // Lifted row-selection state. Persists across filter changes (the
  // table doesn't deselect when filters narrow). Selection takes
  // precedence over filters in the CTA's scope resolution.
  const [selectedIds, setSelectedIds] = useState<ReadonlySet<number>>(
    () => new Set(),
  );
  // Keep the page-level severity dropdown in sync with the filter
  // object so server-side severity narrowing (a query param) and
  // client-side scope (sent to /ai-fixes) stay aligned.
  const handleFilterChange = (next: FindingsFilterState) => {
    setFilter(next);
    setSeverityFilter(next.severityFilter);
  };
  const [pdfDownloading, setPdfDownloading] = useState(false);
  const [csvDownloading, setCsvDownloading] = useState(false);
  const [sarifDownloading, setSarifDownloading] = useState(false);

  const { data: run, isLoading: runLoading, error: runError } = useQuery({
    queryKey: ['run', id],
    queryFn: ({ signal }) => getRun(id, signal),
    enabled: !isNaN(id),
  });

  const { data: findingsData, isLoading: findingsLoading, error: findingsError } = useQuery({
    queryKey: ['findings-enriched', id, severityFilter],
    queryFn: ({ signal }) =>
      getAllEnrichedRunFindings(id, { severity: severityFilter || undefined }, signal),
    enabled: !isNaN(id),
  });
  const findings = findingsData?.findings;
  const findingsTotalCount = findingsData?.totalCount;

  // Pulls the in-app CVE modal feature flag from /api/analysis/config. We
  // default to ``true`` while the config is in flight so the dialog isn't
  // missing on first paint; the flag only flips behaviour when the server
  // explicitly returns ``false`` (rollback path).
  const { data: analysisConfig } = useQuery({
    queryKey: ['analysis-config'],
    queryFn: ({ signal }) => getAnalysisConfig(signal),
    staleTime: 60_000,
  });
  const cveModalEnabled = analysisConfig?.cve_modal_enabled !== false;

  const handleDownloadPdf = async () => {
    if (!run) return;
    setPdfDownloading(true);
    try {
      const blob = await downloadPdfReport({
        runId: run.id,
        title: `Analysis Report — Run #${run.id}`,
        filename: `sbom-analysis-run-${run.id}.pdf`,
      });
      downloadBlob(blob, `sbom-analysis-run-${run.id}.pdf`);
      showToast('PDF report downloaded', 'success');
    } catch (err) {
      showToast(`PDF export failed: ${(err as Error).message}`, 'error');
    } finally {
      setPdfDownloading(false);
    }
  };

  const handleDownloadCsv = async () => {
    if (!run) return;
    setCsvDownloading(true);
    try {
      const { blob, filename } = await exportRunCsv(run.id);
      downloadBlob(blob, filename);
      showToast('CSV exported', 'success');
    } catch (err) {
      showToast(`CSV export failed: ${(err as Error).message}`, 'error');
    } finally {
      setCsvDownloading(false);
    }
  };

  const handleDownloadSarif = async () => {
    if (!run) return;
    setSarifDownloading(true);
    try {
      const { blob, filename } = await exportRunSarif(run.id);
      downloadBlob(blob, filename);
      showToast('SARIF exported', 'success');
    } catch (err) {
      showToast(`SARIF export failed: ${(err as Error).message}`, 'error');
    } finally {
      setSarifDownloading(false);
    }
  };

  if (runLoading) {
    return (
      <div className="flex flex-1 flex-col">
        <TopBar
          title="Analysis run"
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
      <div className="flex flex-1 flex-col">
        <TopBar
          title="Analysis run"
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

  const exportItems = [
    {
      key: 'pdf',
      label: 'PDF report',
      description: 'Polished narrative report — best for sharing',
      Icon: FileBarChart,
      onSelect: handleDownloadPdf,
      loading: pdfDownloading,
      disabled: !run,
    },
    {
      key: 'csv',
      label: 'CSV',
      description: 'All findings — best for spreadsheets',
      Icon: FileSpreadsheet,
      onSelect: handleDownloadCsv,
      loading: csvDownloading,
      disabled: !run,
    },
    {
      key: 'sarif',
      label: 'SARIF',
      description: 'SARIF 2.1.0 — best for code-scanning tools',
      Icon: FileCode2,
      onSelect: handleDownloadSarif,
      loading: sarifDownloading,
      disabled: !run,
    },
  ];

  return (
    <div className="flex flex-1 flex-col">
      <TopBar
        title={`Run #${run.id}`}
        subtitle={run.sbom_name ?? `SBOM #${run.sbom_id ?? '—'}`}
        breadcrumbs={[
          { label: 'Analysis Runs', href: '/analysis' },
          { label: `Run #${run.id}` },
        ]}
        action={<ExportMenu items={exportItems} />}
      />
      <div className="space-y-6 p-6">
        {/* Back */}
        <button
          onClick={() => router.back()}
          className="inline-flex items-center gap-2 text-sm text-hcl-muted transition-colors hover:text-hcl-navy"
        >
          <ArrowLeft className="h-4 w-4" /> Back
        </button>

        {/* Hero */}
        <Motion preset="rise">
          <RunDetailHero run={run} findings={findings} />
        </Motion>

        {/* Run error message — surfaces above findings */}
        {run.error_message && (
          <Alert variant="error" title="Run error">
            {run.error_message}
          </Alert>
        )}

        {/* Outcome footnote */}
        <p className="text-xs leading-relaxed text-hcl-muted">
          Outcome: <span className="text-foreground">{runStatusDescription(run.run_status)}</span>
        </p>

        {/* AI remediation banner — only when the feature flag is enabled.
            Filter + selection state is lifted to this page so the CTA can
            derive its scope (POST /ai-fixes body) from the same filter
            chips and row checkboxes the findings table renders.
            Selection takes precedence over filters when non-empty. */}
        {analysisConfig?.ai_fixes_enabled ? (
          <Motion preset="rise" delay={40}>
            <RunBatchProgress
              runId={id}
              filter={filter}
              selectedIds={Array.from(selectedIds)}
              onClearSelection={() => setSelectedIds(new Set())}
            />
          </Motion>
        ) : null}

        {/* Findings */}
        <Motion preset="rise" delay={80}>
          <Surface variant="elevated">
            <SurfaceHeader>
              <div>
                <h3 className="text-base font-semibold text-hcl-navy">
                  Findings
                  {findingsData != null && (
                    <span className="ml-2 font-metric text-sm font-normal tabular-nums text-hcl-muted">
                      {findingsTotalCount?.toLocaleString() ?? findings?.length ?? 0}
                    </span>
                  )}
                </h3>
                <p className="mt-0.5 text-xs text-hcl-muted">
                  Sortable by risk · expand any row for description, CWE, fix versions.
                </p>
              </div>
            </SurfaceHeader>
            <SurfaceContent className="px-4 py-4">
              {findingsLoading ? (
                <SkeletonTable rows={6} cols={9} />
              ) : (
                <FindingsTable
                  findings={findings}
                  isLoading={false}
                  error={findingsError}
                  onSeverityChange={setSeverityFilter}
                  severityFilter={severityFilter}
                  filter={filter}
                  onFilterChange={handleFilterChange}
                  selectedIds={
                    analysisConfig?.ai_fixes_enabled ? selectedIds : undefined
                  }
                  onSelectionChange={
                    analysisConfig?.ai_fixes_enabled ? setSelectedIds : undefined
                  }
                  runId={id}
                  scanName={run?.sbom_name ?? null}
                  cveModalEnabled={cveModalEnabled}
                  aiFixesEnabled={Boolean(analysisConfig?.ai_fixes_enabled)}
                  aiProviderLabel={analysisConfig?.ai_default_provider ?? undefined}
                />
              )}
            </SurfaceContent>
          </Surface>
        </Motion>
      </div>
    </div>
  );
}
