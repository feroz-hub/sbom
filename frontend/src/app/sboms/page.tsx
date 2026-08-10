'use client';

import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { Upload } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Button } from '@/components/ui/Button';
import { SbomsTable } from '@/components/sboms/SbomsTable';
import { SbomUploadModal } from '@/components/sboms/SbomUploadModal';
import { useSbomsList } from '@/hooks/useSbomsList';
import type { SBOMSource } from '@/types';

export default function SbomsPage() {
  const [showUpload, setShowUpload] = useState(false);
  const queryClient = useQueryClient();

  const { data: sboms, isLoading, error } = useSbomsList();

  /**
   * Called when the upload modal successfully creates an SBOM.
   * The upload modal invalidates the affected query surfaces. This optimistic
   * insert makes the row appear immediately while the refetch follows.
   */
  const handleUploadSuccess = (newSbom: SBOMSource) => {
    queryClient.setQueryData<SBOMSource[]>(['sboms'], (old) => [
      { ...newSbom, _analysisStatus: 'NOT_ANALYSED' as const },
      ...(old ?? []),
    ]);
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
