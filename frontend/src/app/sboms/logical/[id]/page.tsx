'use client';
import { use } from 'react';
import { TopBar } from '@/components/layout/TopBar';
import { LogicalSbomHistory } from '@/components/sboms/LogicalSbomHistory';
export default function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return <div className="flex flex-1 flex-col"><TopBar title="SBOM Version History" breadcrumbs={[{ label: 'SBOMs', href: '/sboms' }]} /><main className="space-y-4 p-6"><LogicalSbomHistory id={Number(id)} /></main></div>;
}
