'use client';

import { useMemo, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Pencil, Trash2 } from 'lucide-react';
import { Alert } from '@/components/ui/Alert';
import { Select } from '@/components/ui/Select';
import { Table, TableHead, TableBody, Th, Td, EmptyRow } from '@/components/ui/Table';
import { TableFilterBar, TableSearchInput } from '@/components/ui/TableFilterBar';
import { Badge } from '@/components/ui/Badge';
import { ConfirmDialog } from '@/components/ui/Dialog';
import { SkeletonRow } from '@/components/ui/Spinner';
import { ProjectModal } from './ProjectModal';
import { deleteProject } from '@/lib/api';
import { matchesMultiField } from '@/lib/tableFilters';
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
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'inactive'>('all');

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

  const filteredProjects = useMemo(() => {
    if (!projects?.length) return [];
    let rows = projects;
    if (statusFilter === 'active') rows = rows.filter((p) => p.project_status === 1);
    if (statusFilter === 'inactive') rows = rows.filter((p) => p.project_status !== 1);
    if (search.trim()) {
      rows = rows.filter((p) =>
        matchesMultiField(search, [
          String(p.id),
          p.project_name,
          p.project_details,
          p.created_by,
          formatDate(p.created_on),
          p.project_status === 1 ? 'active' : 'inactive',
        ]),
      );
    }
    return rows;
  }, [projects, search, statusFilter]);

  const filtersActive = Boolean(search.trim() || statusFilter !== 'all');
  const clearFilters = () => {
    setSearch('');
    setStatusFilter('all');
  };

  if (error) {
    return (
      <Alert variant="error" title="Could not load projects">
        {error.message}
      </Alert>
    );
  }

  const total = projects?.length ?? 0;
  const shown = filteredProjects.length;

  return (
    <>
      <div className="overflow-hidden rounded-xl border border-hcl-border bg-surface shadow-card">
        {!isLoading && total > 0 ? (
          <TableFilterBar
            onClear={clearFilters}
            clearDisabled={!filtersActive}
            resultHint={
              filtersActive ? `Showing ${shown} of ${total}` : `${total} project${total === 1 ? '' : 's'}`
            }
          >
            <TableSearchInput
              value={search}
              onChange={setSearch}
              placeholder="Name, details, ID, author…"
              label="Search"
            />
            <div className="w-full min-w-[10rem] sm:w-44">
              <Select
                label="Status"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value as 'all' | 'active' | 'inactive')}
                className="w-full"
              >
                <option value="all">All statuses</option>
                <option value="active">Active only</option>
                <option value="inactive">Inactive only</option>
              </Select>
            </div>
          </TableFilterBar>
        ) : null}

        <Table striped>
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
            ) : !filteredProjects.length ? (
              <EmptyRow
                cols={7}
                message="No projects match your filters. Try adjusting search or clear filters."
              />
            ) : (
              filteredProjects.map((project) => (
                <tr key={project.id} className="transition-colors hover:bg-hcl-light/40">
                  <Td className="font-mono text-xs text-hcl-muted">#{project.id}</Td>
                  <Td className="font-medium text-hcl-navy">{project.project_name}</Td>
                  <Td>
                    <Badge variant={project.project_status === 1 ? 'success' : 'gray'}>
                      {project.project_status === 1 ? 'Active' : 'Inactive'}
                    </Badge>
                  </Td>
                  <Td className="max-w-xs truncate text-hcl-muted">
                    {project.project_details || '—'}
                  </Td>
                  <Td className="text-hcl-muted">{project.created_by || '—'}</Td>
                  <Td className="whitespace-nowrap text-hcl-muted">{formatDate(project.created_on)}</Td>
                  <Td className="text-right">
                    <div className="flex items-center justify-end gap-2">
                      <button
                        onClick={() => setEditProject(project)}
                        className="rounded-lg p-1.5 text-hcl-muted transition-colors hover:bg-hcl-light hover:text-hcl-blue"
                        aria-label="Edit project"
                      >
                        <Pencil className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => setDeleteId(project.id)}
                        className="rounded-lg p-1.5 text-hcl-muted transition-colors hover:bg-red-50 hover:text-red-600 dark:hover:bg-red-950/40"
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
