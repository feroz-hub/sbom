'use client';

import { useEffect, useMemo, useRef } from 'react';
import { Layers, Play, Sparkles } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { Select } from '@/components/ui/Select';
import { Surface, SurfaceContent, SurfaceHeader } from '@/components/ui/Surface';
import { Motion } from '@/components/ui/Motion';
import { LiveAnalysisCard } from '@/components/analysis/LiveAnalysisCard';
import { SbomPreflightChecklist } from '@/components/analysis/SbomPreflightChecklist';
import { SourceSelector, type SourceKey } from '@/components/analysis/SourceSelector';
import { useAnalysisStream } from '@/hooks/useAnalysisStream';
import type { AnalysisConfig } from '@/lib/api';

export interface ConsolidatedAnalysisPanelProps {
  analysisConfig: AnalysisConfig | undefined;
  sboms: { id: number; sbom_name: string }[] | undefined;
  consolidatedSbomId: string;
  onConsolidatedSbomIdChange: (value: string) => void;
  /** Selected sources (controlled). */
  selectedSources: SourceKey[];
  onSelectedSourcesChange: (next: SourceKey[]) => void;
  /** Called once a run completes so the parent can refetch the runs list. */
  onComplete?: (runId: number) => void;
}

export function ConsolidatedAnalysisPanel({
  analysisConfig,
  sboms,
  consolidatedSbomId,
  onConsolidatedSbomIdChange,
  selectedSources,
  onSelectedSourcesChange,
  onComplete,
}: ConsolidatedAnalysisPanelProps) {
  const sbomIdNumber = useMemo(() => {
    const n = Number(consolidatedSbomId);
    return Number.isFinite(n) && n > 0 ? n : null;
  }, [consolidatedSbomId]);

  const { state, startAnalysis, cancel, reset } = useAnalysisStream(sbomIdNumber ?? 0);

  const isRunning =
    state.phase === 'connecting' || state.phase === 'parsing' || state.phase === 'running';

  // Notify parent exactly once per completed run.
  const lastNotifiedRunIdRef = useRef<number | null>(null);
  useEffect(() => {
    if (state.phase === 'done' && state.runId != null && state.runId !== lastNotifiedRunIdRef.current) {
      lastNotifiedRunIdRef.current = state.runId;
      onComplete?.(state.runId);
    }
  }, [state.phase, state.runId, onComplete]);

  const runDisabled =
    !sbomIdNumber || isRunning || selectedSources.length === 0;

  const startNew = () => {
    if (!sbomIdNumber || selectedSources.length === 0) return;
    startAnalysis({ sources: selectedSources });
  };

  return (
    <div className="space-y-5">
      <Surface variant="elevated" elevation={2} accent>
        <SurfaceHeader>
          <div>
            <h2 className="flex items-center gap-2 text-base font-semibold text-hcl-navy">
              <Sparkles className="h-4 w-4 text-hcl-cyan" aria-hidden />
              Consolidated multi-source analysis
            </h2>
            <p className="mt-0.5 text-xs text-hcl-muted">
              Live-streamed scan across NVD · OSV · GHSA · VulDB with per-source progress.
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
            {/* SBOM picker */}
            <div className="grid grid-cols-1 gap-3 md:grid-cols-[1fr_auto] md:items-end">
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div>
                  <label
                    htmlFor="consolidated-sbom-id"
                    className="mb-1 block text-[11px] font-semibold uppercase tracking-wider text-hcl-muted"
                  >
                    SBOM ID
                  </label>
                  <input
                    id="consolidated-sbom-id"
                    type="number"
                    min={1}
                    placeholder="e.g. 3"
                    value={consolidatedSbomId}
                    onChange={(e) => onConsolidatedSbomIdChange(e.target.value)}
                    disabled={isRunning}
                    className="h-10 w-full rounded-lg border border-border bg-surface px-3 font-metric tabular-nums text-sm text-hcl-navy placeholder:text-hcl-muted disabled:cursor-not-allowed disabled:opacity-60 focus-visible:border-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/30"
                  />
                </div>
                <div>
                  <Select
                    label="Or pick from list"
                    placeholder="Select SBOM…"
                    value={consolidatedSbomId}
                    onChange={(e) => onConsolidatedSbomIdChange(e.target.value)}
                    disabled={isRunning}
                  >
                    {sboms?.map((s) => (
                      <option key={s.id} value={s.id}>
                        #{s.id} — {s.sbom_name}
                      </option>
                    ))}
                  </Select>
                </div>
              </div>
              <Button
                onClick={startNew}
                disabled={runDisabled}
                glow
                size="lg"
                className="md:self-end"
              >
                <Play className="h-4 w-4" aria-hidden />
                {isRunning ? 'Running…' : 'Run analysis'}
              </Button>
            </div>

            {/* Source selector */}
            <SourceSelector
              selected={selectedSources}
              onChange={onSelectedSourcesChange}
              config={analysisConfig}
              disabled={isRunning}
            />

            {selectedSources.length === 0 && (
              <p className="flex items-center gap-1.5 text-[11px] text-amber-700 dark:text-amber-300">
                <Layers className="h-3 w-3" aria-hidden />
                Pick at least one source to enable the run button.
              </p>
            )}
          </div>
        </SurfaceContent>
      </Surface>

      {/* Pre-flight checklist */}
      <Motion preset="rise" delay={80}>
        <SbomPreflightChecklist sbomId={sbomIdNumber} />
      </Motion>

      {/* Live progress / completion */}
      {state.phase !== 'idle' && (
        <Motion preset="rise" delay={120}>
          <LiveAnalysisCard state={state} onCancel={cancel} onReset={reset} />
        </Motion>
      )}
    </div>
  );
}

// Re-export SourceKey for the page component that owns the selection state.
export type { SourceKey };
