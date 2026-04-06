'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Upload } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Button } from '@/components/ui/Button';
import { SbomsTable } from '@/components/sboms/SbomsTable';
import { SbomUploadModal } from '@/components/sboms/SbomUploadModal';
import { getSboms } from '@/lib/api';

export default function SbomsPage() {
  const [showUpload, setShowUpload] = useState(false);

  const { data: sboms, isLoading, error } = useQuery({
    queryKey: ['sboms'],
    queryFn: ({ signal }) => getSboms(1, 50, signal),
  });

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
        <SbomsTable
          sboms={sboms}
          isLoading={isLoading}
          error={error}
        />
      </div>

      <SbomUploadModal
        open={showUpload}
        onClose={() => setShowUpload(false)}
      />
    </div>
  );
}
