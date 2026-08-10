'use client';

import Link from 'next/link';
import { Loader2 } from 'lucide-react';
import { formatDate } from '@/lib/utils';
import type { AnalysisStatus as OptimisticAnalysisStatus } from '@/hooks/useBackgroundAnalysis';
import type { LatestAnalysisSummary } from '@/types';

interface AnalysisStatusBadgeProps {
  sbomId: number;
  analysis?: LatestAnalysisSummary | null;
  optimisticStatus?: OptimisticAnalysisStatus;
  optimisticFindings?: number;
}

type BadgeTone = 'gray' | 'blue' | 'green' | 'yellow' | 'orange' | 'red';

type AnalysisBadgeView = {
  state: 'not_run' | 'queued' | 'running' | 'completed' | 'failed' | 'cancelled' | 'interrupted';
  label: string;
  severitySummary?: string;
  tooltip: string;
  tone: BadgeTone;
  runId?: number | string | null;
  showSpinner?: boolean;
};

const TONE_STYLES: Record<BadgeTone, string> = {
  gray: 'border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-300',
  blue: 'border-blue-200 bg-blue-50 text-blue-700 dark:border-blue-800 dark:bg-blue-950/40 dark:text-blue-200',
  green: 'border-green-200 bg-green-50 text-green-700 dark:border-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-200',
  yellow: 'border-yellow-200 bg-yellow-50 text-yellow-800 dark:border-yellow-800 dark:bg-yellow-950/40 dark:text-yellow-200',
  orange: 'border-orange-200 bg-orange-50 text-orange-800 dark:border-orange-800 dark:bg-orange-950/40 dark:text-orange-200',
  red: 'border-red-200 bg-red-50 text-red-700 dark:border-red-800 dark:bg-red-950/50 dark:text-red-200',
};

function count(value: number | null | undefined): number {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : 0;
}

function pluralFindings(value: number): string {
  return `${value.toLocaleString()} finding${value === 1 ? '' : 's'}`;
}

function normalizeState(analysis: LatestAnalysisSummary): AnalysisBadgeView['state'] {
  const status = String(analysis.status || '').toLowerCase();
  const result = String(analysis.result || '').toLowerCase();
  if (status === 'queued' || status === 'pending' || result === 'queued') return 'queued';
  if (status === 'running' || status === 'analysing' || status === 'analyzing' || result === 'running') return 'running';
  if (status === 'interrupted' || result === 'interrupted') return 'interrupted';
  if (status === 'failed' || status === 'error' || result === 'failed') return 'failed';
  if (status === 'cancelled' || status === 'canceled' || result === 'cancelled' || result === 'canceled') return 'cancelled';
  if (status === 'completed' || result === 'completed' || result === 'pass' || result === 'findings' || result === 'partial') return 'completed';
  return 'completed';
}

function toneForCompleted(analysis: LatestAnalysisSummary): BadgeTone {
  const risk = String(analysis.risk_level || '').toLowerCase();
  if (count(analysis.critical_count) > 0 || risk === 'critical') return 'red';
  if (count(analysis.high_count) > 0 || risk === 'high') return 'orange';
  if (count(analysis.medium_count) > 0 || risk === 'medium') return 'yellow';
  return 'green';
}

function severitySummary(analysis: LatestAnalysisSummary): string | undefined {
  const parts = [
    count(analysis.critical_count) > 0 ? `Critical ${count(analysis.critical_count).toLocaleString()}` : null,
    count(analysis.high_count) > 0 ? `High ${count(analysis.high_count).toLocaleString()}` : null,
    count(analysis.medium_count) > 0 ? `Medium ${count(analysis.medium_count).toLocaleString()}` : null,
    count(analysis.low_count) > 0 ? `Low ${count(analysis.low_count).toLocaleString()}` : null,
  ].filter(Boolean);
  return parts.length ? parts.join(' · ') : undefined;
}

function tooltipForCompleted(analysis: LatestAnalysisSummary, findings: number): string {
  const lines = [
    'Status: Completed',
    `Findings: ${findings.toLocaleString()}`,
    `Critical: ${count(analysis.critical_count).toLocaleString()}`,
    `High: ${count(analysis.high_count).toLocaleString()}`,
    `Medium: ${count(analysis.medium_count).toLocaleString()}`,
    `Low: ${count(analysis.low_count).toLocaleString()}`,
  ];
  if (analysis.risk_level) lines.push(`Risk level: ${String(analysis.risk_level).replaceAll('_', ' ')}`);
  if (analysis.risk_score != null) lines.push(`Risk score: ${Number(analysis.risk_score).toFixed(1)}`);
  if (analysis.completed_at) lines.push(`Completed: ${formatDate(analysis.completed_at)}`);
  if (findings === 0) lines.push('Analysis completed successfully. No findings detected.');
  return lines.join('\n');
}

function viewFromAnalysis(analysis: LatestAnalysisSummary | null | undefined): AnalysisBadgeView {
  if (!analysis) {
    return {
      state: 'not_run',
      label: 'Not Run',
      tooltip: 'Analysis has not been run for this SBOM.',
      tone: 'gray',
    };
  }

  const state = normalizeState(analysis);
  if (state === 'queued') {
    return {
      state,
      label: 'Queued',
      tooltip: 'Analysis is waiting to start.',
      tone: 'blue',
      runId: analysis.run_id,
    };
  }
  if (state === 'running') {
    return {
      state,
      label: 'Running',
      tooltip: 'Analysis is currently running.',
      tone: 'blue',
      runId: analysis.run_id,
      showSpinner: true,
    };
  }
  if (state === 'failed') {
    return {
      state,
      label: 'Failed',
      tooltip: analysis.error_message ? `Status: Failed\nError: ${analysis.error_message}` : 'Status: Failed',
      tone: 'red',
      runId: analysis.run_id,
    };
  }
  if (state === 'interrupted') {
    return {
      state,
      label: 'Interrupted',
      tooltip: analysis.error_message
        ? `Status: Interrupted\nError: ${analysis.error_message}`
        : 'Status: Interrupted',
      tone: 'gray',
      runId: analysis.run_id,
    };
  }
  if (state === 'cancelled') {
    return {
      state,
      label: 'Cancelled',
      tooltip: 'Status: Cancelled',
      tone: 'gray',
      runId: analysis.run_id,
    };
  }

  const findings = count(analysis.finding_count);
  return {
    state,
    label: `Completed · ${pluralFindings(findings)}`,
    severitySummary: severitySummary(analysis),
    tooltip: tooltipForCompleted(analysis, findings),
    tone: toneForCompleted(analysis),
    runId: analysis.run_id,
  };
}

function viewFromOptimisticStatus(
  status?: OptimisticAnalysisStatus,
  findings?: number,
): AnalysisBadgeView | null {
  if (!status) return null;
  if (status === 'ANALYSING' || status === 'RUNNING') {
    return { state: 'running', label: 'Running', tooltip: 'Analysis is currently running.', tone: 'blue', showSpinner: true };
  }
  if (status === 'PENDING' || status === 'QUEUED') {
    return { state: 'queued', label: 'Queued', tooltip: 'Analysis is waiting to start.', tone: 'blue' };
  }
  if (status === 'ERROR') {
    return { state: 'failed', label: 'Failed', tooltip: 'Status: Failed', tone: 'red' };
  }
  if (status === 'INTERRUPTED') {
    return { state: 'interrupted', label: 'Interrupted', tooltip: 'Status: Interrupted', tone: 'gray' };
  }
  if (status === 'NOT_ANALYSED') {
    return { state: 'not_run', label: 'Not Run', tooltip: 'Analysis has not been run for this SBOM.', tone: 'gray' };
  }
  return {
    state: 'completed',
    label: `Completed · ${pluralFindings(count(findings))}`,
    tooltip: `Status: Completed\nFindings: ${count(findings).toLocaleString()}`,
    tone: count(findings) > 0 ? 'orange' : 'green',
  };
}

export function AnalysisStatusBadge({
  sbomId,
  analysis,
  optimisticStatus,
  optimisticFindings,
}: AnalysisStatusBadgeProps) {
  const view = viewFromOptimisticStatus(optimisticStatus, optimisticFindings) ?? viewFromAnalysis(analysis);
  const className = `inline-flex max-w-full cursor-help items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium transition-colors ${TONE_STYLES[view.tone]}`;
  const content = (
    <>
      {view.showSpinner ? <Loader2 className="h-3 w-3 shrink-0 animate-spin" aria-hidden /> : null}
      <span className="min-w-0 truncate">{view.label}</span>
      {view.severitySummary ? <span className="hidden min-w-0 truncate sm:inline">· {view.severitySummary}</span> : null}
    </>
  );

  if (view.runId) {
    return (
      <Link
        href={`/analysis/${view.runId}`}
        className={`${className} hover:underline`}
        title={view.tooltip}
        aria-label={`SBOM ${sbomId}: ${view.tooltip}`}
      >
        {content}
      </Link>
    );
  }

  return (
    <span
      className={className}
      title={view.tooltip}
      aria-label={`SBOM ${sbomId}: ${view.tooltip}`}
    >
      {content}
    </span>
  );
}
