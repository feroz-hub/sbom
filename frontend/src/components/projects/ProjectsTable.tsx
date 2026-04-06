'use client';

import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Pencil, Trash2 } from 'lucide-react';
import { Table, TableHead, TableBody, Th, Td, EmptyRow } from '@/components/ui/Table';
import { Badge } from '@/components/ui/Badge';
import { ConfirmDialog } from '@/components/ui/Dialog';
import { SkeletonRow } from '@/components/ui/Spinner';
import { ProjectModal } from './ProjectModal';
import { deleteProject } from '@/lib/api';
import { formatDate } from '@/lib/utils';
import { useToast } from '@/hooks/useToast';
import type { Project } from '@/types';

interface ProjectsTableProps {
  projects: Project[] | undefined;
  isLoading: boolean;
  error: Error | null;
}

export function ProjectsTable({ projects, isLoading, error }: ProjectsTableProps) {
  const queryClient = useQueryClient();
  const { showToast } = useToast();
  const [editProject, setEditProject] = useState<Project | null>(null);
  const [deleteId, setDeleteId] = useState<number | null>(null);

  const deleteMutation = useMutation({
    mutationFn: (id: number) => deleteProject(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['projects'] });
      showToast('Project deleted successfully', 'success');
      setDeleteId(null);
    },
    onError: (err: Error) => {
      showToast(`Delete failed: ${err.message}`, 'error');
    },
  });

  if (error) {
    return (
      <div className="rounded-lg bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
        Failed to load projects: {error.message}
      </div>
    );
  }

  return (
    <>
      <div className="bg-white rounded-xl border border-hcl-border shadow-card overflow-hidden">
        <Table>
          <TableHead>
            <tr>
              <Th>ID</Th>
              <Th>Name</Th>
              <Th>Status</Th>
              <Th>Details</Th>
              <Th>Created By</Th>
              <Th>Created On</Th>
              <Th className="text-right">Actions</Th>
            </tr>
          </TableHead>
          <TableBody>
            {isLoading ? (
              Array.from({ length: 4 }).map((_, i) => <SkeletonRow key={i} cols={7} />)
            ) : !projects?.length ? (
              <EmptyRow cols={7} message="No projects found. Create your first project!" />
            ) : (
              projects.map((project) => (
                <tr key={project.id} className="hover:bg-hcl-light/40 transition-colors">
                  <Td className="font-mono text-xs text-hcl-muted">#{project.id}</Td>
                  <Td className="font-medium text-hcl-navy">{project.project_name}</Td>
                  <Td>
                    <Badge variant={project.project_status === 'Active' ? 'success' : 'gray'}>
                      {project.project_status}
                    </Badge>
                  </Td>
                  <Td className="max-w-xs truncate text-hcl-muted">
                    {project.project_details || '—'}
                  </Td>
                  <Td className="text-hcl-muted">{project.created_by || '—'}</Td>
                  <Td className="text-hcl-muted whitespace-nowrap">{formatDate(project.created_on)}</Td>
                  <Td className="text-right">
                    <div className="flex items-center justify-end gap-2">
                      <button
                        onClick={() => setEditProject(project)}
                        className="p-1.5 text-hcl-muted hover:text-hcl-blue hover:bg-hcl-light rounded-lg transition-colors"
                        aria-label="Edit project"
                      >
                        <Pencil className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => setDeleteId(project.id)}
                        className="p-1.5 text-hcl-muted hover:text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                        aria-label="Delete project"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </Td>
                </tr>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      {editProject && (
        <ProjectModal
          open={!!editProject}
          onClose={() => setEditProject(null)}
          project={editProject}
        />
      )}

      <ConfirmDialog
        open={deleteId !== null}
        onClose={() => setDeleteId(null)}
        onConfirm={() => deleteId !== null && deleteMutation.mutate(deleteId)}
        title="Delete Project"
        message="Are you sure you want to delete this project? This action cannot be undone."
        confirmLabel="Delete Project"
        loading={deleteMutation.isPending}
      />
    </>
  );
}
