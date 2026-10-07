'use client';

import { Suspense, useCallback, useMemo, useState } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import { Plus } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Button } from '@/components/ui/Button';
import { ProjectsTable } from '@/components/projects/ProjectsTable';
import { ProjectModal } from '@/components/projects/ProjectModal';
import { ProjectApplications } from '@/components/projects/ProjectApplications';
import { getDashboardScannedProjectIds, getProjects, type DashboardFilterScope } from '@/lib/api';
import type { Project } from '@/types';

export default function ProjectsPage() {
  return <Suspense fallback={null}><ProjectsContent /></Suspense>;
}

function ProjectsContent() {
  const [showCreate, setShowCreate] = useState(false);
  const [visibleIds, setVisibleIds] = useState<number[] | null>(null);
  const params = useSearchParams();
  const router = useRouter();
  // Existing dashboard scope is retained. Selection has a separate URL key,
  // so selecting a card never changes scanned/application/SBOM filtering.
  const projectId = Number(params?.get('project')) || null;
  const applicationId = projectId ? Number(params?.get('product')) || null : null;
  const sbomId = applicationId ? Number(params?.get('sbom')) || null : null;
  const scanned = params?.get('scanned') === '1';
  const requestedId = Number(params?.get('selectedProject')) || projectId;
  const scope: DashboardFilterScope = { projectId, applicationId, sbomId };

  const { data: projects, isLoading, error } = useQuery({ queryKey: ['projects'], queryFn: ({ signal }) => getProjects(signal) });
  const scannedProjects = useQuery({ queryKey: ['dashboard-scanned-projects', projectId, applicationId, sbomId], queryFn: ({ signal }) => getDashboardScannedProjectIds(scope, signal), enabled: scanned });
  const visibleProjects = useMemo(() => {
    const scannedIds = scanned ? new Set(scannedProjects.data?.ids ?? []) : null;
    return projects?.filter(project => (!projectId || project.id === projectId) && (!scannedIds || scannedIds.has(project.id)));
  }, [projects, projectId, scanned, scannedProjects.data]);
  const pageLoading = isLoading || (scanned && scannedProjects.isLoading);
  const pageError = error || (scanned ? scannedProjects.error : null);
  const resultProjects = visibleIds === null ? visibleProjects : visibleProjects?.filter(project => visibleIds.includes(project.id));
  const selected = resultProjects?.find(project => project.id === requestedId) ?? resultProjects?.find(project => project.id === visibleIds?.[0]) ?? resultProjects?.[0];
  const onVisibleIdsChange = useCallback((ids: number[]) => setVisibleIds(previous => previous?.length === ids.length && previous.every((id, index) => id === ids[index]) ? previous : ids), []);
  function selectProject(project: Project) {
    const next = new URLSearchParams(params?.toString());
    next.set('selectedProject', String(project.id));
    router.push(`/projects?${next.toString()}`, { scroll: false });
  }

  return <div className="flex min-w-0 flex-1 flex-col">
    <TopBar title="Projects" action={<Button onClick={() => setShowCreate(true)}><Plus className="h-4 w-4" />New Project</Button>} />
    <div className="min-w-0 space-y-5 p-3 md:p-6">
      <p className="text-sm text-hcl-muted">Select a project to manage its applications and SBOMs.</p>
      <ProjectsTable projects={visibleProjects} isLoading={pageLoading} error={pageError} initialProjectId={requestedId} selectedId={selected?.id} onSelect={selectProject} onVisibleIdsChange={onVisibleIdsChange} onCreate={() => setShowCreate(true)} />
      {!pageLoading && !pageError && selected ? <section aria-label="Application inventory"><ProjectApplications key={selected.id} project={selected} /></section> : !pageLoading && !pageError && visibleProjects?.length ? <p className="text-sm text-hcl-muted">Select a matching project to view its applications.</p> : null}
    </div>
    <ProjectModal open={showCreate} onClose={() => setShowCreate(false)} />
  </div>;
}
