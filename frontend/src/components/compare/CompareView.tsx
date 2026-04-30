'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import { ArrowLeft, Download } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { TopBar } from '@/components/layout/TopBar';
import { compareRunsV2 } from '@/lib/api';
import { useCompareUrlState } from '@/hooks/useCompareUrlState';
import {
  COMPARE_ERR_PERMISSION_DENIED,
  COMPARE_ERR_RUN_NOT_FOUND,
  COMPARE_ERR_RUN_NOT_READY,
  COMPARE_ERR_SAME_RUN,
  type RunSummary,
} from '@/types/compare';
import { HttpError } from '@/lib/api';
import { SelectionBar } from './SelectionBar/SelectionBar';
import { PostureHero } from './PostureHero/PostureHero';
import { IdenticalRunsCard, isIdenticalRuns } from './IdenticalRunsCard/IdenticalRunsCard';
import { TabsAdaptive } from './TabsAdaptive/TabsAdaptive';
import { FindingsTab } from './FindingsTab/FindingsTab';
import { ComponentsTab } from './ComponentsTab/ComponentsTab';
import { PostureDetailTab } from './PostureDetailTab/PostureDetailTab';
import {
  CompareSkeleton,
  EmptySelectionState,
  GenericCompareError,
  PermissionDeniedState,
  RunNotFoundState,
  RunNotReadyState,
  SameRunPickedState,
} from './states/CompareStates';
import { ExportDialog } from './ExportDialog';
import { KeyboardShortcutsOverlay } from './KeyboardShortcutsOverlay';

export function CompareView() {
  const router = useRouter();
  const urlState = useCompareUrlState();
  const [exportOpen, setExportOpen] = useState(false);

  const canQuery =
    urlState.runA != null &&
    urlState.runB != null &&
    urlState.runA !== urlState.runB;

  const { data, isLoading, error } = useQuery({
    queryKey: ['compare', 'v2', urlState.runA, urlState.runB],
    queryFn: ({ signal }) =>
      compareRunsV2(
        { run_a_id: urlState.runA as number, run_b_id: urlState.runB as number },
        signal,
      ),
    enabled: canQuery,
    staleTime: 10 * 60 * 1000,
    gcTime: 60 * 60 * 1000,
  });

  // We hold light "summary" copies of each side from the picker so the
  // SelectionBar can render the relationship descriptor + the picker-paired
  // project filter even before the compare query resolves.
  const [aPick, setAPick] = useState<RunSummary | null>(null);
  const [bPick, setBPick] = useState<RunSummary | null>(null);

  // When the compare result arrives, hydrate the picks from the canonical
  // server response so the labels match what the diff is actually computed on.
  useEffect(() => {
    if (data) {
      setAPick(data.run_a);
      setBPick(data.run_b);
    }
  }, [data]);

  const handleSelectA = (run: RunSummary) => {
    setAPick(run);
    urlState.setRuns(run.id, urlState.runB);
  };
  const handleSelectB = (run: RunSummary) => {
    setBPick(run);
    urlState.setRuns(urlState.runA, run.id);
  };

  const subtitle = canQuery
    ? `Run #${urlState.runA} vs Run #${urlState.runB}`
    : 'Diff two analysis runs';

  // Surface specific error envelopes — the API returns structured detail
  // objects per ADR-0008. Anything we don't recognise falls through to the
  // generic alert.
  const errorView = (() => {
    if (!error) return null;
    if (error instanceof HttpError) {
      const code = (error as HttpError).code;
      if (code === COMPARE_ERR_SAME_RUN) {
        return <SameRunPickedState runId={urlState.runA ?? 0} />;
      }
      if (code === COMPARE_ERR_RUN_NOT_FOUND) {
        return <RunNotFoundState />;
      }
      if (code === COMPARE_ERR_RUN_NOT_READY) {
        return <RunNotReadyState />;
      }
      if (code === COMPARE_ERR_PERMISSION_DENIED) {
        return <PermissionDeniedState />;
      }
    }
    return <GenericCompareError message={(error as Error).message} />;
  })();

  return (
    <div className="flex flex-1 flex-col">
      <TopBar
        title="Compare runs"
        subtitle={subtitle}
        breadcrumbs={[
          { label: 'Analysis Runs', href: '/analysis' },
          { label: 'Compare' },
        ]}
      />
      <div className="space-y-4 p-6">
        <div className="flex items-center justify-between gap-2">
          <button
            onClick={() => router.back()}
            className="inline-flex items-center gap-2 text-sm text-hcl-muted transition-colors hover:text-hcl-navy"
          >
            <ArrowLeft className="h-4 w-4" /> Back
          </button>
          {data && (
            <Button
              variant="secondary"
              onClick={() => setExportOpen(true)}
              className="inline-flex items-center gap-1.5"
            >
              <Download className="h-4 w-4" aria-hidden /> Export
            </Button>
          )}
        </div>

        <SelectionBar
          runAId={urlState.runA}
          runBId={urlState.runB}
          runASummary={data?.run_a ?? aPick}
          runBSummary={data?.run_b ?? bPick}
          relationship={data?.relationship ?? null}
          onSelectRunA={handleSelectA}
          onSelectRunB={handleSelectB}
          onSwap={urlState.swap}
          onShare={urlState.shareUrl}
        />

        {!canQuery && urlState.runA != null && urlState.runA === urlState.runB && (
          <SameRunPickedState runId={urlState.runA} />
        )}

        {!canQuery && (urlState.runA == null || urlState.runB == null) && (
          <EmptySelectionState />
        )}

        {canQuery && isLoading && <CompareSkeleton />}

        {canQuery && errorView}

        {canQuery && data && (
          <>
            {isIdenticalRuns(data) ? (
              <IdenticalRunsCard
                result={data}
                onViewSharedFindings={urlState.showSharedFindings}
              />
            ) : (
              <PostureHero
                posture={data.posture}
                relationship={data.relationship}
                sharedSbomId={data.relationship.same_sbom ? data.run_b.sbom_id : null}
                currentRunId={data.run_b.id}
                sharedSbomName={data.run_b.sbom_name ?? null}
              />
            )}

            <TabsAdaptive
              current={urlState.tab}
              setTab={urlState.setTab}
              result={data}
            />

            {urlState.tab === 'findings' && <FindingsTab result={data} />}
            {urlState.tab === 'components' && <ComponentsTab result={data} />}
            {urlState.tab === 'delta' && <PostureDetailTab result={data} />}

            <ExportDialog
              open={exportOpen}
              onClose={() => setExportOpen(false)}
              cacheKey={data.cache_key}
            />
            <KeyboardShortcutsOverlay
              setTab={urlState.setTab}
              onOpenExport={() => setExportOpen(true)}
            />
          </>
        )}
      </div>
    </div>
  );
}
