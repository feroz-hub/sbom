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
    <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
      <TopBar
        title="Repair Workspace"
        breadcrumbs={[{ label: 'SBOMs', href: '/sboms' }, { label: 'Repair Workspace' }]}
      />
      <div className="min-h-0 flex-1 overflow-hidden px-6 py-4">
        <ValidationRepairWorkspace sessionId={workspaceId} />
      </div>
    </div>
  );
}
