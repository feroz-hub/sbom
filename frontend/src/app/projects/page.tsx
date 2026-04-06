'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Plus } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Button } from '@/components/ui/Button';
import { ProjectsTable } from '@/components/projects/ProjectsTable';
import { ProjectModal } from '@/components/projects/ProjectModal';
import { getProjects } from '@/lib/api';

export default function ProjectsPage() {
  const [showCreate, setShowCreate] = useState(false);

  const { data: projects, isLoading, error } = useQuery({
    queryKey: ['projects'],
    queryFn: ({ signal }) => getProjects(signal),
  });

  return (
    <div className="flex flex-col flex-1">
      <TopBar
        title="Projects"
        action={
          <Button onClick={() => setShowCreate(true)}>
            <Plus className="h-4 w-4" />
            New Project
          </Button>
        }
      />
      <div className="p-6">
        <ProjectsTable
          projects={projects}
          isLoading={isLoading}
          error={error}
        />
      </div>

      <ProjectModal
        open={showCreate}
        onClose={() => setShowCreate(false)}
      />
    </div>
  );
}
