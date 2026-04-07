'use client';

import { use } from 'react';
import { useQuery } from '@tanstack/react-query';
import { TopBar } from '@/components/layout/TopBar';
import { PageSpinner } from '@/components/ui/Spinner';
import { SbomDetail } from '@/components/sboms/SbomDetail';
import { getSbom } from '@/lib/api';

interface SbomDetailPageProps {
  params: Promise<{ id: string }>;
}

export default function SbomDetailPage({ params }: SbomDetailPageProps) {
  const { id: idParam } = use(params);
  const id = Number(idParam);

  const { data: sbom, isLoading, error } = useQuery({
    queryKey: ['sbom', id],
    queryFn: ({ signal }) => getSbom(id, signal),
    enabled: !isNaN(id),
  });

  if (isLoading) {
    return (
      <div className="flex flex-col flex-1">
        <TopBar title="SBOM Detail" />
        <div className="p-6">
          <PageSpinner />
        </div>
      </div>
    );
  }

  if (error || !sbom) {
    return (
      <div className="flex flex-col flex-1">
        <TopBar title="SBOM Detail" />
        <div className="p-6">
          <div className="rounded-lg bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
            {error ? `Failed to load SBOM: ${error.message}` : 'SBOM not found'}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col flex-1">
      <TopBar title={sbom.sbom_name} />
      <div className="p-6">
        <SbomDetail sbom={sbom} />
      </div>
    </div>
  );
}
