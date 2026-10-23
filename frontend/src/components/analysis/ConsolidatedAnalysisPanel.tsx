'use client';

import { recordIdLabel } from '@/components/ui/RecordIdDisplay';
import { useEffect, useMemo, useRef, type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Layers, Play, Sparkles } from 'lucide-react';
import { PermissionButton as Button } from '@/components/ui/PermissionButton';
import { Select } from '@/components/ui/Select';
import { Surface, SurfaceContent, SurfaceHeader } from '@/components/ui/Surface';
import { Alert } from '@/components/ui/Alert';
import { Skeleton } from '@/components/ui/Spinner';
import { SelectedSbomContext } from './SelectedSbomContext';
import { useAuth } from '@/hooks/useAuth';
import { formatDate } from '@/lib/utils';
import Link from 'next/link';
import { isActiveAnalysis } from '@/lib/analysisSync';
import { LiveAnalysisCard } from '@/components/analysis/LiveAnalysisCard';
import { SbomPreflightChecklist } from '@/components/analysis/SbomPreflightChecklist';
import { SourceSelector, type SourceKey } from '@/components/analysis/SourceSelector';
import { useAnalysisStream } from '@/hooks/useAnalysisStream';
import { getSbom, type AnalysisConfig } from '@/lib/api';
import type { SBOMSource } from '@/types';

export interface ConsolidatedAnalysisPanelProps {
  analysisConfig: AnalysisConfig | undefined;
  sboms: SBOMSource[] | undefined;
  scopeControls?: ReactNode;
  isLoading?: boolean;
  error?: Error | null;
  onRetry?: () => void;
  consolidatedSbomId: string;
  onConsolidatedSbomIdChange: (value: string) => void;
  /** Selected sources (controlled). */
  selectedSources: SourceKey[];
  onSelectedSourcesChange: (next: SourceKey[]) => void;
  /** Called once a run completes so the parent can refetch the runs list. */
  onComplete?: (runId: string) => void;
}

export function ConsolidatedAnalysisPanel({
  analysisConfig,
  sboms,
  scopeControls, isLoading, error, onRetry,
  consolidatedSbomId,
  onConsolidatedSbomIdChange,
  selectedSources,
  onSelectedSourcesChange,
  onComplete,
}: ConsolidatedAnalysisPanelProps) {
  const sbomIdNumber = useMemo(() => {
    const n = consolidatedSbomId;
    return n || null;
  }, [consolidatedSbomId]);

  const { activeTenantId, activeTenant } = useAuth();
  const selected = useQuery({
    queryKey: ['sbom', consolidatedSbomId, activeTenantId],
    queryFn: ({ signal }) => getSbom(consolidatedSbomId, signal),
    enabled: !!consolidatedSbomId && !!activeTenantId,
    refetchInterval: query => isActiveAnalysis(query.state.data?.latest_analysis?.status) ? 5000 : false,
  });
  const { state, startAnalysis, cancel, reset } = useAnalysisStream(sbomIdNumber ?? 0);
  const availableSources = selectedSources.filter(source => source !== 'GITHUB' || analysisConfig?.github_configured);
  const existingActiveRun = isActiveAnalysis(selected.data?.latest_analysis?.status);

  const isRunning =
    state.phase === 'connecting' || state.phase === 'parsing' || state.phase === 'running';

  // Notify parent exactly once per completed run.
  const lastNotifiedRunIdRef = useRef<string | null>(null);
  useEffect(() => {
    if (state.phase === 'done' && state.runId != null && state.runId !== lastNotifiedRunIdRef.current) {
      lastNotifiedRunIdRef.current = state.runId;
      onComplete?.(state.runId);
    }
  }, [state.phase, state.runId, onComplete]);

  const runDisabled =
    !selected.data || selected.isFetching || isRunning || existingActiveRun || isLoading || !analysisConfig || availableSources.length === 0
    || selected.data.processing_eligibility?.eligible === false;

  const startNew = () => {
    if (runDisabled) return;
    startAnalysis({ sources: availableSources });
  };

  return (
    <div className="space-y-5">
      <Surface variant="elevated" elevation={2} accent>
        <SurfaceHeader>
          <div>
            <h2 className="flex items-center gap-2 text-base font-semibold text-hcl-navy">
              <Sparkles className="h-4 w-4 text-hcl-cyan" aria-hidden />
              Analysis configuration
            </h2>
            <p className="mt-0.5 text-xs text-hcl-muted">
              Select a validated SBOM and the vulnerability sources to query.
            </p>
          </div>
          {isRunning && (
            <span className="inline-flex items-center gap-1.5 rounded-full bg-sky-50 px-3 py-1 text-[11px] font-semibold uppercase tracking-wider text-sky-700 ring-1 ring-sky-300/60 dark:bg-sky-950/40 dark:text-sky-300 dark:ring-sky-900/60">
              <span className="h-1.5 w-1.5 rounded-full bg-sky-500 pulse-dot text-sky-500" aria-hidden />
              Live
            </span>
          )}
        </SurfaceHeader>
        <SurfaceContent>
          <div className="space-y-5">
            <p className="text-xs text-hcl-muted">Active tenant: <strong className="text-hcl-navy">{activeTenant?.name || 'Unavailable'}</strong></p>
            <fieldset disabled={isRunning || isLoading} className="min-w-0 space-y-4">
              <legend className="sr-only">Analysis scope</legend>
              {scopeControls}
              <div className="grid grid-cols-1 gap-3 md:grid-cols-[minmax(0,1fr)_auto] md:items-end">
                <Select label="SBOM" aria-label="SBOM" placeholder="Select SBOM…" value={consolidatedSbomId}
                  onChange={event => onConsolidatedSbomIdChange(event.target.value)} disabled={isRunning || isLoading}>
                  <option value="">Select SBOM…</option>
                  {sboms?.map(sbom => <option key={sbom.id} value={sbom.id}>
                    {recordIdLabel('SBOM', sbom.display_id)} — {sbom.sbom_name}{sbom.sbom_version || sbom.productver ? ` · ${sbom.sbom_version || sbom.productver}` : ''}
                  </option>)}
                  {selected.data && !sboms?.some(sbom => String(sbom.id) === consolidatedSbomId) && <option value={consolidatedSbomId}>{selected.data.sbom_name}</option>}
                </Select>
                <Button permission="analysis:run" disabledReason={existingActiveRun ? 'An analysis is already queued or running for this SBOM. View the latest attempt below.' : selected.data?.processing_eligibility?.reason || 'Select an eligible SBOM and at least one available source.'}
                  onClick={startNew} disabled={runDisabled} glow size="lg" className="md:self-end">
                  <Play className="h-4 w-4" aria-hidden />{isRunning ? 'Running…' : 'Run analysis'}
                </Button>
              </div>
            </fieldset>
            {isLoading && <Skeleton className="h-5 w-full" />}
            {error && <Alert variant="error" title="Analysis configuration unavailable">{error.message}{onRetry && <button type="button" className="ml-2 underline" onClick={onRetry}>Retry configuration</button>}</Alert>}
            {!isLoading && !error && !sboms?.length && <p className="text-sm text-hcl-muted">No SBOMs in this scope. Select another project or upload a validated SBOM.</p>}
            {selected.isLoading && <Skeleton className="h-12 w-full" />}
            {selected.error && <Alert variant="error" title="Selected SBOM unavailable">{selected.error.message}</Alert>}
            {selected.data && <dl className="grid gap-3 rounded-lg border border-border bg-surface-muted p-3 text-sm sm:grid-cols-3">
              {[['Selected version', selected.data.sbom_version || selected.data.productver || 'Unavailable'],
                ['Format', selected.data.format || selected.data.detected_format || 'Unavailable'],
                ['Uploaded', formatDate(selected.data.created_on)]].map(([label, value]) => <div key={label} className="min-w-0"><dt className="text-xs text-hcl-muted">{label}</dt><dd className="mt-1 break-words font-medium text-hcl-navy">{value}</dd></div>)}
            </dl>}
            {selected.data?.latest_analysis && <p className="flex flex-wrap items-center gap-2 text-xs text-hcl-muted" role="status">
              <span>Latest attempt: <strong className="text-hcl-navy">{selected.data.latest_analysis.status.replaceAll('_', ' ')}</strong></span>
              {selected.data.latest_analysis.completed_at && <span>· {formatDate(selected.data.latest_analysis.completed_at)}</span>}
              {selected.data.latest_analysis.run_id && <Link className="font-medium text-primary underline" href={`/analysis/${selected.data.latest_analysis.run_id}`}>View latest attempt</Link>}
            </p>}
            {selected.data?.processing_eligibility?.eligible === false && <Alert variant="warning">{selected.data.processing_eligibility.reason || 'This SBOM is not eligible for analysis.'}</Alert>}

            {/* Source selector */}
            <SourceSelector
              selected={selectedSources}
              onChange={onSelectedSourcesChange}
              config={analysisConfig}
              disabled={isRunning}
            />

            {availableSources.length === 0 && (
              <p className="flex items-center gap-1.5 text-[11px] text-amber-700 dark:text-amber-300">
                <Layers className="h-3 w-3" aria-hidden />
                Pick at least one source to enable the run button.
              </p>
            )}
          </div>
        </SurfaceContent>
      </Surface>

      {state.phase !== 'idle' && <section aria-label="Analysis execution" aria-live="polite">
        <LiveAnalysisCard state={state} onCancel={() => { cancel(); void selected.refetch(); }} onReset={reset} />
      </section>}
      {selected.data && <SelectedSbomContext sbom={selected.data} />}
      <details className="rounded-xl border border-border bg-surface">
        <summary className="cursor-pointer px-5 py-3 text-sm font-medium text-hcl-navy focus-visible:outline focus-visible:outline-primary">SBOM scan readiness</summary>
        <SbomPreflightChecklist sbomId={sbomIdNumber} />
      </details>
    </div>
  );
}

export type { SourceKey };
