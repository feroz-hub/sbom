'use client';

import { Suspense, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useSearchParams } from 'next/navigation';
import { Upload } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Button } from '@/components/ui/Button';
import { SbomsTable } from '@/components/sboms/SbomsTable';
import { SbomUploadModal } from '@/components/sboms/SbomUploadModal';
import { useSbomsList } from '@/hooks/useSbomsList';
import { getSboms, type DashboardFilterScope } from '@/lib/api';
import type { SBOMSource } from '@/types';

export default function SbomsPage() {
  return <Suspense fallback={null}><SbomsContent /></Suspense>;
}

function SbomsContent() {
  const [showUpload, setShowUpload] = useState(false);
  const queryClient = useQueryClient();
  const params = useSearchParams();
  const projectId = Number(params?.get('project')) || null;
  const applicationId = projectId ? Number(params?.get('product')) || null : null;
  const sbomId = applicationId ? Number(params?.get('sbom')) || null : null;
  const analysed = params?.get('analysed') === '1';
  const scope: DashboardFilterScope = { projectId, applicationId, sbomId };
  const isScoped = projectId != null || analysed;

  const allSboms = useSbomsList({ enabled: !isScoped });
  const scopedSboms = useQuery({
    queryKey: ['sboms', 'dashboard-scope', projectId, applicationId, sbomId, analysed],
    queryFn: ({ signal }) => getSboms(1, 500, signal, scope, analysed),
    enabled: isScoped,
  });
  const { data: sboms, isLoading, error } = isScoped ? scopedSboms : allSboms;

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
