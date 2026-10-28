import type { AnalysisStatus } from '@/hooks/useBackgroundAnalysis';
import type { LatestAnalysis } from '@/types';
import { AnalysisStatusBadge } from './AnalysisStatusBadge';

interface SbomStatusBadgeProps {
  sbomId: (string | number);
  displayId?: number | null;
  initialStatus?: AnalysisStatus;
  initialFindings?: number;
  latestAnalysis?: LatestAnalysis | null;
}

export function SbomStatusBadge({ sbomId, displayId, initialStatus, initialFindings, latestAnalysis }: SbomStatusBadgeProps) {
  return (
    <AnalysisStatusBadge
      sbomId={sbomId} displayId={displayId}
      analysis={latestAnalysis}
      optimisticStatus={initialStatus}
      optimisticFindings={initialFindings}
    />
  );
}
