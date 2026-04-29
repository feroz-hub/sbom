'use client';

import { useQuery } from '@tanstack/react-query';
import { TopBar } from '@/components/layout/TopBar';
import { Alert } from '@/components/ui/Alert';
import { PageSpinner } from '@/components/ui/Spinner';
import { SbomDetail } from '@/components/sboms/SbomDetail';
import { getSbom } from '@/lib/api';

interface SbomDetailPageProps {
  params: { id: string };
}

export default function SbomDetailPage({ params }: SbomDetailPageProps) {
  const id = Number(params.id);

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
        <TopBar title="SBOM Detail" breadcrumbs={[{ label: 'SBOMs', href: '/sboms' }]} />
        <div className="p-6">
          <Alert variant="error" title={error ? 'Could not load SBOM' : 'Not found'}>
            {error ? error.message : 'This SBOM does not exist or was removed.'}
          </Alert>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col flex-1">
      <TopBar title={sbom.sbom_name} breadcrumbs={[{ label: 'SBOMs', href: '/sboms' }]} />
      <div className="p-6">
        <SbomDetail sbom={sbom} />
      </div>
    </div>
  );
}
