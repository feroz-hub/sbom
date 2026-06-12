'use client';

import { use } from 'react';
import { TopBar } from '@/components/layout/TopBar';
import { ValidationRepairWorkspace } from '@/components/sboms/ValidationRepairWorkspace';

interface ValidationRepairPageProps {
  params: Promise<{ id: string }>;
}

export default function ValidationRepairPage({ params }: ValidationRepairPageProps) {
  const { id } = use(params);

  return (
    <div className="flex flex-col flex-1">
      <TopBar
        title="Validation Repair Workspace"
        breadcrumbs={[{ label: 'SBOMs', href: '/sboms' }, { label: 'Repair Workspace' }]}
      />
      <div className="p-6">
        <ValidationRepairWorkspace sessionId={id} />
      </div>
    </div>
  );
}
