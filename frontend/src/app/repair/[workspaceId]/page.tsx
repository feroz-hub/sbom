'use client';

import { use } from 'react';
import { Breadcrumb } from '@/components/layout/Breadcrumb';
import { ValidationRepairWorkspace } from '@/components/sboms/ValidationRepairWorkspace';

interface RepairPageProps {
  params: Promise<{ workspaceId: string }>;
}

export default function RepairPage({ params }: RepairPageProps) {
  const { workspaceId } = use(params);

  return (
    <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
      <Breadcrumb className="shrink-0 px-3 pt-3 md:px-4 xl:px-6" items={[{ label: 'SBOMs', href: '/sboms' }, { label: 'Repair Workspace' }]} />
      <div className="min-h-0 flex-1 overflow-auto px-3 py-3 md:px-4 md:py-4 xl:px-6">
        <ValidationRepairWorkspace key={workspaceId} sessionId={workspaceId} />
      </div>
    </div>
  );
}
