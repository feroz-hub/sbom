'use client';

import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { Upload } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Button } from '@/components/ui/Button';
import { SbomsTable } from '@/components/sboms/SbomsTable';
import { SbomUploadModal } from '@/components/sboms/SbomUploadModal';
import { useSbomsList } from '@/hooks/useSbomsList';
import { useBackgroundAnalysis } from '@/hooks/useBackgroundAnalysis';
import { usePendingAnalysisRecovery } from '@/hooks/usePendingAnalysisRecovery';
import type { SBOMSource } from '@/types';

export default function SbomsPage() {
  const [showUpload, setShowUpload] = useState(false);
  const queryClient = useQueryClient();
  const { triggerBackgroundAnalysis } = useBackgroundAnalysis();

  const { data: sboms, isLoading, error } = useSbomsList();

  // On mount: resume any analysis jobs that were running before a page refresh
  usePendingAnalysisRecovery(triggerBackgroundAnalysis);

  /**
   * Called when the upload modal successfully creates an SBOM.
   * 1. Inject the new SBOM into the React Query cache immediately (optimistic)
   * 2. Fire background analysis — never blocks the user
   */
  const handleUploadSuccess = (newSbom: SBOMSource) => {
    // Optimistic: add to list with ANALYSING status before any refetch
    queryClient.setQueryData<SBOMSource[]>(['sboms'], (old) => [
      { ...newSbom, _analysisStatus: 'ANALYSING' as const },
      ...(old ?? []),
    ]);

    // Background analysis — toast + badge update happen automatically
    triggerBackgroundAnalysis(newSbom.id, newSbom.sbom_name);
  };

  return (
    <div className="flex flex-col flex-1">
      <TopBar
        title="SBOMs"
        action={
          <Button onClick={() => setShowUpload(true)}>
            <Upload className="h-4 w-4" />
            Upload SBOM
          </Button>
        }
      />
      <div className="p-6">
        <SbomsTable sboms={sboms} isLoading={isLoading} error={error} />
      </div>

      <SbomUploadModal
        open={showUpload}
        onClose={() => setShowUpload(false)}
        onSuccess={handleUploadSuccess}
      />
    </div>
  );
}
