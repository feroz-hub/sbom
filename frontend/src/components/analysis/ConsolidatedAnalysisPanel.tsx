'use client';

import { Play, Download, AlertTriangle } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { Select } from '@/components/ui/Select';
import { Input } from '@/components/ui/Input';
import type { ConsolidatedAnalysisResult } from '@/types';
import type { AnalysisConfig } from '@/lib/api';

export interface ConsolidatedAnalysisPanelProps {
  analysisConfig: AnalysisConfig | undefined;
  sboms: { id: number; sbom_name: string }[] | undefined;
  consolidatedSbomId: string;
  onConsolidatedSbomIdChange: (value: string) => void;
  consolidatedResult: ConsolidatedAnalysisResult | null;
  onRunAnalysis: () => void;
  analysisPending: boolean;
  runDisabled: boolean;
  onDownloadPdf: () => void;
  pdfDownloading: boolean;
}

export function ConsolidatedAnalysisPanel({
  analysisConfig,
  sboms,
  consolidatedSbomId,
  onConsolidatedSbomIdChange,
  consolidatedResult,
  onRunAnalysis,
  analysisPending,
  runDisabled,
  onDownloadPdf,
  pdfDownloading,
}: ConsolidatedAnalysisPanelProps) {
  return (
    <div className="bg-surface rounded-xl border border-hcl-border shadow-card overflow-hidden">
      <div className="px-6 py-4 border-b-2 border-hcl-border bg-hcl-light/40 flex items-center gap-2.5">
        <div className="w-1 h-5 rounded-full bg-hcl-cyan shrink-0" />
        <h2 className="text-base font-semibold text-hcl-navy">
          Consolidated Analysis (NVD + GHSA + OSV + VulDB)
        </h2>
      </div>
      <div className="px-6 py-5 space-y-4">
        <p className="text-sm text-hcl-muted">
          Run a full multi-source vulnerability scan against the configured databases simultaneously.
        </p>
        {analysisConfig && !analysisConfig.github_configured && (
          <div className="flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-200">
            <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0" />
            <span>
              <strong>GitHub Advisory (GHSA) requires a GitHub token.</strong>{' '}
              Set <code className="font-mono text-xs bg-amber-100 dark:bg-amber-900/50 px-1 rounded">GITHUB_TOKEN</code>{' '}
              in your backend <code className="font-mono text-xs bg-amber-100 dark:bg-amber-900/50 px-1 rounded">.env</code>{' '}
              file to include GHSA findings. Proceeding without it will skip GitHub findings.
            </span>
          </div>
        )}
        {analysisConfig && !analysisConfig.vulndb_configured && (
          <div className="flex items-start gap-2 rounded-lg border border-cyan-200 bg-cyan-50 px-4 py-3 text-sm text-cyan-900 dark:border-cyan-900 dark:bg-cyan-950/40 dark:text-cyan-100">
            <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0" />
            <span>
              <strong>VulDB requires an API key.</strong>{' '}
              Set <code className="font-mono text-xs bg-cyan-100 dark:bg-cyan-900/50 px-1 rounded">VULNDB_API_KEY</code>{' '}
              in your backend <code className="font-mono text-xs bg-cyan-100 dark:bg-cyan-900/50 px-1 rounded">.env</code>{' '}
              file to include VulDB findings.
            </span>
          </div>
        )}
        <div className="flex items-end gap-3 flex-wrap">
          <div className="w-48">
            <Input
              label="SBOM ID"
              placeholder="e.g. 3"
              value={consolidatedSbomId}
              onChange={(e) => onConsolidatedSbomIdChange(e.target.value)}
              type="number"
              min="1"
            />
          </div>
          <div className="w-56">
            <Select
              label="Or pick SBOM"
              placeholder="Select SBOM..."
              value={consolidatedSbomId}
              onChange={(e) => onConsolidatedSbomIdChange(e.target.value)}
            >
              {sboms?.map((s) => (
                <option key={s.id} value={s.id}>
                  #{s.id} — {s.sbom_name}
                </option>
              ))}
            </Select>
          </div>
          <Button onClick={onRunAnalysis} loading={analysisPending} disabled={runDisabled}>
            <Play className="h-4 w-4" />
            Run Analysis
          </Button>
        </div>

        {consolidatedResult && (
          <div className="mt-2 space-y-3">
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
              {[
                { label: 'Run ID', value: consolidatedResult.runId },
                { label: 'Components', value: consolidatedResult.total_components ?? '—' },
                { label: 'With CPE', value: consolidatedResult.components_with_cpe ?? '—' },
                { label: 'Total Found', value: consolidatedResult.total_findings ?? '—' },
                { label: 'Critical', value: consolidatedResult.critical_count ?? 0 },
                { label: 'High', value: consolidatedResult.high_count ?? 0 },
              ].map(({ label, value }) => (
                <div key={label} className="bg-hcl-light rounded-lg px-4 py-3 border border-hcl-border">
                  <p className="text-xs font-medium text-hcl-muted">{label}</p>
                  <p className="mt-0.5 text-xl font-bold text-hcl-navy">{value}</p>
                </div>
              ))}
            </div>
            <div className="flex items-center gap-2">
              <Button variant="secondary" size="sm" onClick={onDownloadPdf} loading={pdfDownloading}>
                <Download className="h-4 w-4" />
                Download PDF Report
              </Button>
              <span className="text-xs text-hcl-muted">Run #{consolidatedResult.runId}</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
