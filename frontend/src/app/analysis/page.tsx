'use client';

import { useState, useMemo, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { useQuery, useMutation } from '@tanstack/react-query';
import { Play, Download, FileJson, AlertTriangle, CheckCircle2, XCircle, ActivityIcon, Layers, GitCompareArrows } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Button } from '@/components/ui/Button';
import { Select } from '@/components/ui/Select';
import { Input } from '@/components/ui/Input';
import { Card, CardContent } from '@/components/ui/Card';
import { RunsTable } from '@/components/analysis/RunsTable';
import { getRuns, getProjects, getSboms, analyzeConsolidated, downloadPdfReport, exportRunsJson, getAnalysisConfig } from '@/lib/api';
import { runStatusShortLabel } from '@/lib/analysisRunStatusLabels';
import { downloadBlob } from '@/lib/utils';
import { useToast } from '@/hooks/useToast';
import type { ConsolidatedAnalysisResult } from '@/types';

export default function AnalysisPage() {
  const { showToast } = useToast();
  const router = useRouter();

  // ── Filters ────────────────────────────────────────────────────────────────
  const [projectFilter, setProjectFilter] = useState('');
  const [sbomFilter, setSbomFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');

  // ── Multi-select state for Compare Runs ───────────────────────────────────
  const [selectedForCompare, setSelectedForCompare] = useState<Set<number>>(new Set());

  const toggleSelectForCompare = useCallback((id: number) => {
    setSelectedForCompare((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        // Cap at 2 — oldest entry drops out so it always feels responsive.
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

  // ── Consolidated analysis ──────────────────────────────────────────────────
  const [consolidatedSbomId, setConsolidatedSbomId] = useState('');
  const [consolidatedResult, setConsolidatedResult] = useState<ConsolidatedAnalysisResult | null>(null);
  const [pdfDownloading, setPdfDownloading] = useState(false);

  const { data: analysisConfig } = useQuery({
    queryKey: ['analysis-config'],
    queryFn: ({ signal }) => getAnalysisConfig(signal),
    staleTime: 60_000,
  });

  const { data: projects } = useQuery({
    queryKey: ['projects'],
    queryFn: ({ signal }) => getProjects(signal),
  });

  const { data: sboms } = useQuery({
    queryKey: ['sboms'],
    queryFn: ({ signal }) => getSboms(1, 100, signal),
  });

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
        signal
      ),
  });

  // ── Summary metrics derived from loaded runs ───────────────────────────────
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

  // ── Consolidated analysis mutation ─────────────────────────────────────────
  const consolidateMutation = useMutation({
    mutationFn: () => {
      const id = Number(consolidatedSbomId);
      if (!id) throw new Error('Please enter a valid SBOM ID');
      const sbom = sboms?.find((s) => s.id === id);
      return analyzeConsolidated({ sbom_id: id, sbom_name: sbom?.sbom_name ?? `SBOM #${id}` });
    },
    onSuccess: (result) => {
      setConsolidatedResult(result);
      showToast('Consolidated analysis complete', 'success');
      refetch();
    },
    onError: (err: Error) => {
      showToast(`Analysis failed: ${err.message}`, 'error');
    },
  });

  const handleDownloadConsolidatedPdf = async () => {
    if (!consolidatedResult?.runId) return;
    setPdfDownloading(true);
    try {
      const blob = await downloadPdfReport({
        runId: consolidatedResult.runId,
        title: `Consolidated Analysis — SBOM #${consolidatedSbomId}`,
        filename: `sbom-consolidated-${consolidatedSbomId}.pdf`,
      });
      downloadBlob(blob, `sbom-consolidated-${consolidatedSbomId}.pdf`);
      showToast('PDF downloaded', 'success');
    } catch (err) {
      showToast(`PDF failed: ${(err as Error).message}`, 'error');
    } finally {
      setPdfDownloading(false);
    }
  };

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

        {/* ── Summary metric cards ─────────────────────────────────────────── */}
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

        {/* ── Filters ─────────────────────────────────────────────────────── */}
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
              onClick={() => { setProjectFilter(''); setSbomFilter(''); setStatusFilter(''); }}
              className="text-sm text-hcl-muted hover:text-hcl-navy underline"
            >
              Clear filters
            </button>
          )}
        </div>

        {/* ── Runs table ───────────────────────────────────────────────────── */}
        <RunsTable
          runs={runs}
          isLoading={isLoading}
          error={error}
          selectedIds={selectedForCompare}
          onToggleSelect={toggleSelectForCompare}
        />

        {/* ── Consolidated Analysis ────────────────────────────────────────── */}
        <div className="bg-surface rounded-xl border border-hcl-border shadow-card overflow-hidden">
          <div className="px-6 py-4 border-b-2 border-hcl-border bg-hcl-light/40 flex items-center gap-2.5">
            <div className="w-1 h-5 rounded-full bg-hcl-cyan shrink-0" />
            <h2 className="text-base font-semibold text-hcl-navy">Consolidated Analysis (NVD + GHSA + OSV)</h2>
          </div>
          <div className="px-6 py-5 space-y-4">
            <p className="text-sm text-hcl-muted">
              Run a full multi-source vulnerability scan against all three databases simultaneously.
            </p>
            {analysisConfig && !analysisConfig.github_configured && (
              <div className="flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
                <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0" />
                <span>
                  <strong>GitHub Advisory (GHSA) requires a GitHub token.</strong>{' '}
                  Set <code className="font-mono text-xs bg-amber-100 px-1 rounded">GITHUB_TOKEN</code> in your
                  backend <code className="font-mono text-xs bg-amber-100 px-1 rounded">.env</code> file to include
                  GHSA findings. Proceeding without it will skip GitHub findings.
                </span>
              </div>
            )}
            <div className="flex items-end gap-3 flex-wrap">
              <div className="w-48">
                <Input
                  label="SBOM ID"
                  placeholder="e.g. 3"
                  value={consolidatedSbomId}
                  onChange={(e) => setConsolidatedSbomId(e.target.value)}
                  type="number"
                  min="1"
                />
              </div>
              {/* Quick-pick from loaded SBOMs */}
              <div className="w-56">
                <Select
                  label="Or pick SBOM"
                  placeholder="Select SBOM..."
                  value={consolidatedSbomId}
                  onChange={(e) => setConsolidatedSbomId(e.target.value)}
                >
                  {sboms?.map((s) => (
                    <option key={s.id} value={s.id}>
                      #{s.id} — {s.sbom_name}
                    </option>
                  ))}
                </Select>
              </div>
              <Button
                onClick={() => consolidateMutation.mutate()}
                loading={consolidateMutation.isPending}
                disabled={!consolidatedSbomId}
              >
                <Play className="h-4 w-4" />
                Run Analysis
              </Button>
            </div>

            {/* Results */}
            {consolidatedResult && (
              <div className="mt-2 space-y-3">
                <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
                  {[
                    { label: 'Run ID',      value: consolidatedResult.runId },
                    { label: 'Components',  value: consolidatedResult.total_components ?? '—' },
                    { label: 'With CPE',    value: consolidatedResult.components_with_cpe ?? '—' },
                    { label: 'Total Found', value: consolidatedResult.total_findings ?? '—' },
                    { label: 'Critical',    value: consolidatedResult.critical_count ?? 0 },
                    { label: 'High',        value: consolidatedResult.high_count ?? 0 },
                  ].map(({ label, value }) => (
                    <div key={label} className="bg-hcl-light rounded-lg px-4 py-3 border border-hcl-border">
                      <p className="text-xs font-medium text-hcl-muted">{label}</p>
                      <p className="mt-0.5 text-xl font-bold text-hcl-navy">{value}</p>
                    </div>
                  ))}
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={handleDownloadConsolidatedPdf}
                    loading={pdfDownloading}
                  >
                    <Download className="h-4 w-4" />
                    Download PDF Report
                  </Button>
                  <span className="text-xs text-hcl-muted">Run #{consolidatedResult.runId}</span>
                </div>
              </div>
            )}
          </div>
        </div>

      </div>
    </div>
  );
}
