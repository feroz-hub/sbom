'use client';

import { use } from 'react';
import { TopBar } from '@/components/layout/TopBar';
import { ValidationRepairWorkspace } from '@/components/sboms/ValidationRepairWorkspace';

interface RepairPageProps {
  params: Promise<{ workspaceId: string }>;
}

export default function RepairPage({ params }: RepairPageProps) {
  const { workspaceId } = use(params);

  return (
    <div className="flex flex-col flex-1">
      <TopBar
        title="Repair Workspace"
        breadcrumbs={[{ label: 'SBOMs', href: '/sboms' }, { label: 'Repair Workspace' }]}
      />
      <div className="p-6">
        <ValidationRepairWorkspace sessionId={workspaceId} />
      </div>
    </div>
  );
}
