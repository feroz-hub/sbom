'use client';

import { ArrowRight, Link2, Shuffle } from 'lucide-react';
import { Surface, SurfaceContent } from '@/components/ui/Surface';
import { useToast } from '@/hooks/useToast';
import type { RunRelationship, RunSummary } from '@/types/compare';
import { RelationshipDescriptor } from './RelationshipDescriptor';
import { RunPicker } from './RunPicker';

interface SelectionBarProps {
  runAId: number | null;
  runBId: number | null;
  runASummary: RunSummary | null;
  runBSummary: RunSummary | null;
  relationship: RunRelationship | null;
  onSelectRunA: (run: RunSummary) => void;
  onSelectRunB: (run: RunSummary) => void;
  onSwap: () => void;
  onShare: () => string;
}

export function SelectionBar({
  runAId,
  runBId,
  runASummary,
  runBSummary,
  relationship,
  onSelectRunA,
  onSelectRunB,
  onSwap,
  onShare,
}: SelectionBarProps) {
  const { showToast } = useToast();

  const handleShare = async () => {
    const url = onShare();
    if (!url) return;
    try {
      await navigator.clipboard.writeText(url);
      showToast('Link copied to clipboard', 'success');
    } catch {
      showToast('Could not copy link', 'error');
    }
  };

  return (
    <Surface variant="elevated" className="sticky top-2 z-20">
      <SurfaceContent className="space-y-3 py-4">
        <div className="grid grid-cols-1 items-end gap-3 lg:grid-cols-[1fr_auto_1fr_auto]">
          <RunPicker
            label="Run A · baseline"
            selectedRunId={runAId}
            onSelect={onSelectRunA}
          />
          <div
            aria-hidden
            className="hidden items-center justify-center pb-2 text-hcl-muted lg:flex"
          >
            <ArrowRight className="h-4 w-4" />
          </div>
          <RunPicker
            label="Run B · candidate"
            selectedRunId={runBId}
            onSelect={onSelectRunB}
            pairedRunProjectId={runASummary?.project_id ?? null}
            align="right"
          />
          <div className="flex items-center gap-2 pb-1">
            <button
              type="button"
              onClick={onSwap}
              disabled={runAId == null || runBId == null}
              className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-surface px-3 py-2 text-xs font-medium text-hcl-navy transition-colors hover:bg-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/30 disabled:cursor-not-allowed disabled:opacity-50"
              aria-label="Swap Run A and Run B"
            >
              <Shuffle className="h-3.5 w-3.5" aria-hidden />
              Swap
            </button>
            <button
              type="button"
              onClick={handleShare}
              disabled={runAId == null || runBId == null}
              className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-surface px-3 py-2 text-xs font-medium text-hcl-navy transition-colors hover:bg-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/30 disabled:cursor-not-allowed disabled:opacity-50"
              aria-label="Copy shareable URL"
            >
              <Link2 className="h-3.5 w-3.5" aria-hidden />
              Share
            </button>
          </div>
        </div>
        {relationship && (
          <RelationshipDescriptor
            relationship={relationship}
            onSwap={onSwap}
          />
        )}
      </SurfaceContent>
    </Surface>
  );
}
