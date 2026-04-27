'use client';

import { CheckCircle2, XCircle, Loader2, Clock, AlertTriangle, ChevronRight } from 'lucide-react';
import { useRouter } from 'next/navigation';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { formatDuration } from '@/lib/utils';
import type { AnalysisStreamState, SourceProgress } from '@/hooks/useAnalysisStream';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function formatElapsed(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const secs = Math.floor(ms / 1000);
  if (secs < 60) return `${secs}s`;
  const mins = Math.floor(secs / 60);
  return `${mins}m ${secs % 60}s`;
}

const SOURCE_LABELS: Record<string, string> = {
  NVD: 'NVD (NIST)',
  OSV: 'OSV Database',
  GITHUB: 'GitHub Advisories',
  VULNDB: 'VulDB',
};

// ─── SourceRow ────────────────────────────────────────────────────────────────

function SourceRow({ source }: { source: SourceProgress }) {
  const label = SOURCE_LABELS[source.name] ?? source.name;

  const icon = () => {
    switch (source.status) {
      case 'running':
        return <Loader2 className="h-4 w-4 text-hcl-blue animate-spin" />;
      case 'complete':
        return <CheckCircle2 className="h-4 w-4 text-green-500" />;
      case 'error':
        return <XCircle className="h-4 w-4 text-red-500" />;
      case 'skipped':
        return <AlertTriangle className="h-4 w-4 text-amber-400" />;
      default:
        return <div className="h-4 w-4 rounded-full border-2 border-hcl-border" />;
    }
  };

  const rowBg =
    source.status === 'running'
      ? 'bg-blue-50 border-blue-200'
      : source.status === 'complete'
        ? 'bg-green-50 border-green-200'
        : source.status === 'error'
          ? 'bg-red-50 border-red-200'
          : 'bg-surface border-hcl-border';

  return (
    <div className={`flex items-center gap-3 px-4 py-3 rounded-lg border ${rowBg} transition-colors`}>
      <div className="shrink-0">{icon()}</div>

      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-hcl-navy">{label}</p>
        {source.status === 'running' && (
          <p className="text-xs text-hcl-muted mt-0.5 animate-pulse">Querying…</p>
        )}
        {source.status === 'complete' && (
          <p className="text-xs text-hcl-muted mt-0.5">
            {source.findings.toLocaleString()} finding{source.findings !== 1 ? 's' : ''}
            {source.errors > 0 && `, ${source.errors} error${source.errors !== 1 ? 's' : ''}`}
          </p>
        )}
        {source.status === 'error' && (
          <p className="text-xs text-red-600 mt-0.5 truncate">{source.error ?? 'Source failed'}</p>
        )}
      </div>

      <div className="shrink-0 text-right">
        {(source.status === 'complete' || source.status === 'error') && source.sourceMs > 0 && (
          <span className="text-xs text-hcl-muted">{formatDuration(source.sourceMs)}</span>
        )}
        {source.status === 'complete' && source.findings > 0 && (
          <div className="mt-0.5">
            <span className="text-sm font-bold text-hcl-navy">{source.findings.toLocaleString()}</span>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

interface AnalysisProgressProps {
  state: AnalysisStreamState;
  onCancel?: () => void;
  onReset?: () => void;
}

export function AnalysisProgress({ state, onCancel, onReset }: AnalysisProgressProps) {
  const router = useRouter();
  const { phase, components, sources, elapsedMs, runId, summary, error } = state;

  if (phase === 'idle') return null;

  const sourceList = Object.values(sources);
  const isRunning = phase === 'connecting' || phase === 'parsing' || phase === 'running';
  const isDone = phase === 'done';
  const isError = phase === 'error';

  // Phase label
  const phaseLabel = () => {
    if (phase === 'connecting') return 'Connecting…';
    if (phase === 'parsing') return 'Parsing SBOM…';
    if (phase === 'running') return 'Running analysis…';
    if (phase === 'done') return 'Analysis complete';
    if (phase === 'error') return 'Analysis failed';
    return '';
  };

  return (
    <div className="rounded-xl border border-hcl-border bg-surface shadow-card overflow-hidden">
      {/* Header */}
      <div className="px-5 py-4 border-b border-hcl-border bg-hcl-light/40 flex items-center gap-3">
        <div className="w-1 h-5 rounded-full bg-hcl-blue shrink-0" />
        <div className="flex-1 min-w-0">
          <p className="text-sm font-semibold text-hcl-navy">{phaseLabel()}</p>
          {components > 0 && (
            <p className="text-xs text-hcl-muted mt-0.5">{components} components</p>
          )}
        </div>
        {/* Elapsed timer */}
        <div className="flex items-center gap-1.5 text-xs text-hcl-muted shrink-0">
          <Clock className="h-3.5 w-3.5" />
          <span className="font-mono tabular-nums">{formatElapsed(elapsedMs)}</span>
        </div>
      </div>

      {/* Per-source rows */}
      {sourceList.length > 0 && (
        <div className="p-4 space-y-2">
          {sourceList.map((src) => (
            <SourceRow key={src.name} source={src} />
          ))}
        </div>
      )}

      {/* Parsing indicator (before sources start) */}
      {phase === 'parsing' && sourceList.every((s) => s.status === 'pending') && (
        <div className="px-4 pb-4">
          <div className="flex items-center gap-2 text-sm text-hcl-muted">
            <Loader2 className="h-4 w-4 animate-spin text-hcl-blue" />
            Parsing SBOM and preparing queries…
          </div>
        </div>
      )}

      {/* Error state */}
      {isError && error && (
        <div className="px-4 pb-4">
          <Alert variant="error" title="Analysis failed">
            {error}
          </Alert>
        </div>
      )}

      {/* Summary on completion */}
      {isDone && summary && (
        <div className="px-4 pb-4">
          <div className="grid grid-cols-3 sm:grid-cols-6 gap-2">
            {[
              { label: 'Total', value: summary.total, cls: 'text-hcl-navy' },
              { label: 'Critical', value: summary.critical, cls: 'text-red-600' },
              { label: 'High', value: summary.high, cls: 'text-orange-600' },
              { label: 'Medium', value: summary.medium, cls: 'text-amber-600' },
              { label: 'Low', value: summary.low, cls: 'text-blue-600' },
              { label: 'Unknown', value: summary.unknown, cls: 'text-slate-500' },
            ].map(({ label, value, cls }) => (
              <div key={label} className="text-center rounded-lg bg-hcl-light border border-hcl-border py-2 px-1">
                <p className="text-xs text-hcl-muted">{label}</p>
                <p className={`text-lg font-bold ${cls}`}>{value.toLocaleString()}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Footer actions */}
      <div className="px-4 py-3 border-t border-hcl-border bg-hcl-light/40 flex items-center justify-between gap-3">
        <div className="text-xs text-hcl-muted">
          {isDone && runId && `Run #${runId} · ${formatDuration(elapsedMs)}`}
        </div>
        <div className="flex items-center gap-2">
          {isRunning && onCancel && (
            <Button variant="secondary" size="sm" onClick={onCancel}>
              Cancel
            </Button>
          )}
          {(isDone || isError) && onReset && (
            <Button variant="secondary" size="sm" onClick={onReset}>
              Run Again
            </Button>
          )}
          {isDone && runId && (
            <Button
              size="sm"
              onClick={() => router.push(`/analysis/${runId}`)}
            >
              View Results <ChevronRight className="h-4 w-4" />
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}
