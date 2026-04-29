'use client';

import { Loader2 } from 'lucide-react';
import { sbomAnalysisDescription, sbomAnalysisShortLabel } from '@/lib/analysisRunStatusLabels';
import type { AnalysisStatus } from '@/hooks/useBackgroundAnalysis';

interface SbomStatusBadgeProps {
  sbomId: number;
  initialStatus?: AnalysisStatus;
  initialFindings?: number;
}

// ADR-0001: FINDINGS replaces FAIL and paints amber (a successful scan that
// produced security output, not a pipeline failure). ERROR keeps red.
const _CLEAN_STYLE = 'border-green-200 bg-green-50 text-green-700 dark:border-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-200';
const _FINDINGS_STYLE = 'border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-800 dark:bg-amber-950/50 dark:text-amber-200';
const STATUS_STYLES: Record<AnalysisStatus, string> = {
  ANALYSING: 'border-blue-200 bg-blue-50 text-blue-700 dark:border-blue-800 dark:bg-blue-950/40 dark:text-blue-200',
  OK: _CLEAN_STYLE,
  PASS: _CLEAN_STYLE, // legacy alias
  FINDINGS: _FINDINGS_STYLE,
  FAIL: _FINDINGS_STYLE, // legacy alias
  PARTIAL: 'border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-800 dark:bg-amber-950/50 dark:text-amber-200',
  ERROR: 'border-red-200 bg-red-50 text-red-600 dark:border-red-800 dark:bg-red-950/50 dark:text-red-200',
  NOT_ANALYSED: 'border-slate-200 bg-slate-50 text-slate-500 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-400',
};

/**
 * Displays analysis status from parent row data. Updates when the SBOM list query cache changes.
 */
export function SbomStatusBadge({ sbomId, initialStatus, initialFindings }: SbomStatusBadgeProps) {
  const status: AnalysisStatus = initialStatus ?? 'NOT_ANALYSED';
  const findings = initialFindings;

  if (status === 'NOT_ANALYSED') {
    return <span className="text-xs text-hcl-muted">—</span>;
  }

  const styles = STATUS_STYLES[status];
  const label = sbomAnalysisShortLabel(status);
  const help = sbomAnalysisDescription(status);

  return (
    <span
      className={`inline-flex max-w-full cursor-help items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium ${styles}`}
      title={help}
      aria-label={`SBOM ${sbomId}: ${help}`}
    >
      {status === 'ANALYSING' && <Loader2 className="h-3 w-3 shrink-0 animate-spin" aria-hidden />}
      <span className="min-w-0 truncate">{label}</span>
      {status !== 'ANALYSING' && findings !== undefined && findings > 0 && (
        <span className="font-bold tabular-nums">{findings}</span>
      )}
    </span>
  );
}
