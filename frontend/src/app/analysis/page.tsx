'use client';

import { Suspense, useCallback, useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import {
  FileJson,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  ActivityIcon,
  Layers,
  GitCompareArrows,
} from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Button } from '@/components/ui/Button';
import { Select } from '@/components/ui/Select';
import { RunsTable } from '@/components/analysis/RunsTable';
import {
  ConsolidatedAnalysisPanel,
  type SourceKey,
} from '@/components/analysis/ConsolidatedAnalysisPanel';
import { AnalysisHubTabs } from '@/components/analysis/AnalysisHubTabs';
import { PageSpinner } from '@/components/ui/Spinner';
import {
  getRuns,
  getProjects,
  exportRunsJson,
  getAnalysisConfig,
} from '@/lib/api';
import { runStatusShortLabel } from '@/lib/analysisRunStatusLabels';
import { useToast } from '@/hooks/useToast';
import { useAnalysisUrlState } from '@/hooks/useAnalysisUrlState';
import { useSbomsList } from '@/hooks/useSbomsList';

const DEFAULT_SOURCES: SourceKey[] = ['NVD', 'OSV', 'GITHUB', 'VULNDB'];

function AnalysisPageInner() {
  const { showToast } = useToast();
  const router = useRouter();

  const {
    projectFilter,
    sbomFilter,
    statusFilter,
    hubTab,
    setProjectFilter,
    setSbomFilter,
    setStatusFilter,
    setHubTab,
    clearFilters,
  } = useAnalysisUrlState();

  const [selectedForCompare, setSelectedForCompare] = useState<Set<number>>(new Set());
  const [selectedSources, setSelectedSources] = useState<SourceKey[]>(DEFAULT_SOURCES);

  const toggleSelectForCompare = useCallback((id: number) => {
    setSelectedForCompare((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        if (next.size >= 2) {
          const first = next.values().next().value;
          if (first !== undefined) next.delete(first);
        }
        next.add(id);
      }
      return next;
    });
  }, []);

  const handleCompare = () => {
    if (selectedForCompare.size !== 2) return;
    const [a, b] = Array.from(selectedForCompare);
    router.push(`/analysis/compare?run_a=${a}&run_b=${b}`);
  };

  const { data: analysisConfig } = useQuery({
    queryKey: ['analysis-config'],
    queryFn: ({ signal }) => getAnalysisConfig(signal),
    staleTime: 60_000,
  });

  const { data: projects } = useQuery({
    queryKey: ['projects'],
    queryFn: ({ signal }) => getProjects(signal),
  });

  const { data: sboms } = useSbomsList();

  const { data: runs, isLoading, error, refetch } = useQuery({
    queryKey: ['runs', { projectFilter, sbomFilter, statusFilter }],
    queryFn: ({ signal }) =>
      getRuns(
        {
          project_id: projectFilter ? Number(projectFilter) : undefined,
          sbom_id: sbomFilter ? Number(sbomFilter) : undefined,
          run_status: statusFilter || undefined,
          page: 1,
          page_size: 100,
        },
        signal,
      ),
  });

  const summary = useMemo(() => {
    if (!runs) return null;
    return {
      total: runs.length,
      pass: runs.filter((r) => r.run_status === 'PASS').length,
      fail: runs.filter((r) => r.run_status === 'FAIL').length,
      partial: runs.filter((r) => r.run_status === 'PARTIAL').length,
      errors: runs.filter((r) => r.run_status === 'ERROR').length,
      findings: runs.reduce((s, r) => s + (r.total_findings ?? 0), 0),
    };
  }, [runs]);

  const handleAnalysisComplete = useCallback(
    (runId: number) => {
      showToast(`Run #${runId} complete`, 'success');
      refetch();
    },
    [showToast, refetch],
  );

  const handleExportJson = async () => {
    try {
      await exportRunsJson({
        project_id: projectFilter ? Number(projectFilter) : undefined,
        sbom_id: sbomFilter ? Number(sbomFilter) : undefined,
        run_status: statusFilter || undefined,
      });
      showToast('Exported as JSON', 'success');
    } catch (err) {
      showToast(`Export failed: ${(err as Error).message}`, 'error');
    }
  };

  return (
    <div className="flex flex-col flex-1">
      <TopBar
        title="Analysis Runs"
        action={
          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={handleCompare}
              disabled={selectedForCompare.size !== 2}
              title={
                selectedForCompare.size === 2
                  ? 'Compare the two selected runs'
                  : `Select exactly 2 runs to compare (${selectedForCompare.size}/2)`
              }
            >
              <GitCompareArrows className="h-4 w-4" />
              Compare {selectedForCompare.size > 0 ? `(${selectedForCompare.size}/2)` : ''}
            </Button>
            <Button variant="secondary" size="sm" onClick={handleExportJson}>
              <FileJson className="h-4 w-4" />
              Export JSON
            </Button>
          </div>
        }
      />
      <div className="p-6 space-y-5">
        <AnalysisHubTabs active={hubTab} onChange={setHubTab} />

        {hubTab === 'consolidated' && (
          <div
            role="tabpanel"
            id="analysis-panel-consolidated"
            aria-labelledby="analysis-tab-consolidated"
          >
            <ConsolidatedAnalysisPanel
              analysisConfig={analysisConfig}
              sboms={sboms}
              consolidatedSbomId={sbomFilter}
              onConsolidatedSbomIdChange={setSbomFilter}
              selectedSources={selectedSources}
              onSelectedSourcesChange={setSelectedSources}
              onComplete={handleAnalysisComplete}
            />
          </div>
        )}

        {hubTab === 'runs' && (
          <div
            role="tabpanel"
            id="analysis-panel-runs"
            aria-labelledby="analysis-tab-runs"
            className="space-y-5"
          >
            {summary && (
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
                {[
                  {
                    label: 'Total runs',
                    hint: 'All loaded runs in the table below.',
                    value: summary.total,
                    icon: Layers,
                    color: 'text-hcl-blue  bg-hcl-light',
                    border: 'border-l-hcl-blue',
                  },
                  {
                    label: 'Runs — no issues',
                    hint: 'Runs that reported zero vulnerabilities (PASS).',
                    value: summary.pass,
                    icon: CheckCircle2,
                    color: 'text-green-600 bg-green-50',
                    border: 'border-l-green-500',
                  },
                  {
                    label: 'Runs — with findings',
                    hint: 'Runs where at least one vulnerability was reported (FAIL). Not a system failure.',
                    value: summary.fail,
                    icon: XCircle,
                    color: 'text-red-600   bg-red-50',
                    border: 'border-l-red-500',
                  },
                  {
                    label: 'Runs — source errors',
                    hint: 'Runs with lookup/API issues; findings may be incomplete (PARTIAL).',
                    value: summary.partial,
                    icon: ActivityIcon,
                    color: 'text-amber-600 bg-amber-50',
                    border: 'border-l-amber-500',
                  },
                  {
                    label: 'Runs — failed',
                    hint: 'Runs that ended in ERROR.',
                    value: summary.errors,
                    icon: AlertTriangle,
                    color: 'text-orange-600 bg-orange-50',
                    border: 'border-l-orange-500',
                  },
                  {
                    label: 'Total findings',
                    hint: 'Sum of vulnerability counts across loaded runs.',
                    value: summary.findings,
                    icon: AlertTriangle,
                    color: 'text-red-600   bg-red-50',
                    border: 'border-l-red-500',
                  },
                ].map(({ label, hint, value, icon: Icon, color, border }) => (
                  <div
                    key={label}
                    title={hint}
                    className={`bg-surface rounded-xl border border-hcl-border shadow-card border-l-4 ${border} px-4 py-3`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="min-w-0">
                        <p className="text-xs font-medium text-hcl-muted">{label}</p>
                        <p className="mt-0.5 text-2xl font-bold text-hcl-navy">{value.toLocaleString()}</p>
                      </div>
                      <div className={`p-2 rounded-lg ${color}`}>
                        <Icon className="h-4 w-4" />
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}

            <div className="flex flex-wrap gap-3 bg-surface rounded-xl border border-hcl-border shadow-card p-4">
              <Select
                value={projectFilter}
                onChange={(e) => setProjectFilter(e.target.value)}
                className="w-52"
                placeholder="All Projects"
              >
                {projects?.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.project_name}
                  </option>
                ))}
              </Select>

              <Select
                value={sbomFilter}
                onChange={(e) => setSbomFilter(e.target.value)}
                className="w-52"
                placeholder="All SBOMs"
              >
                {sboms?.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.sbom_name}
                  </option>
                ))}
              </Select>

              <Select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="w-56"
                placeholder="All outcomes"
              >
                <option value="">All outcomes</option>
                <option value="PASS">{runStatusShortLabel('PASS')}</option>
                <option value="FAIL">{runStatusShortLabel('FAIL')}</option>
                <option value="PARTIAL">{runStatusShortLabel('PARTIAL')}</option>
                <option value="NO_DATA">{runStatusShortLabel('NO_DATA')}</option>
                <option value="ERROR">{runStatusShortLabel('ERROR')}</option>
                <option value="RUNNING">{runStatusShortLabel('RUNNING')}</option>
                <option value="PENDING">{runStatusShortLabel('PENDING')}</option>
              </Select>

              {(projectFilter || sbomFilter || statusFilter) && (
                <button
                  type="button"
                  onClick={clearFilters}
                  className="text-sm text-hcl-muted hover:text-hcl-navy underline"
                >
                  Clear filters
                </button>
              )}
            </div>

            <RunsTable
              runs={runs}
              isLoading={isLoading}
              error={error}
              selectedIds={selectedForCompare}
              onToggleSelect={toggleSelectForCompare}
            />
          </div>
        )}
      </div>
    </div>
  );
}

export default function AnalysisPage() {
  return (
    <Suspense
      fallback={
        <div className="flex flex-col flex-1">
          <TopBar title="Analysis Runs" />
          <div className="flex flex-1 items-center justify-center p-12">
            <PageSpinner />
          </div>
        </div>
      }
    >
      <AnalysisPageInner />
    </Suspense>
  );
}
