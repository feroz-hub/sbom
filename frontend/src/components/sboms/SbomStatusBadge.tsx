import type { AnalysisStatus } from '@/hooks/useBackgroundAnalysis';
import type { LatestAnalysis } from '@/types';
import { AnalysisStatusBadge } from './AnalysisStatusBadge';

interface SbomStatusBadgeProps {
  sbomId: number;
  initialStatus?: AnalysisStatus;
  initialFindings?: number;
  latestAnalysis?: LatestAnalysis | null;
}

export function SbomStatusBadge({ sbomId, initialStatus, initialFindings, latestAnalysis }: SbomStatusBadgeProps) {
  return (
    <AnalysisStatusBadge
      sbomId={sbomId}
      analysis={latestAnalysis}
      optimisticStatus={initialStatus}
      optimisticFindings={initialFindings}
    />
  );
}
