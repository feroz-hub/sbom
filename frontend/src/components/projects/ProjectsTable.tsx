'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { InventoryActionMenu } from './InventoryActionMenu';
import { Alert } from '@/components/ui/Alert';
import { Select } from '@/components/ui/Select';
import { ViewToggle } from '@/components/ui/ViewToggle';
import { Table, TableHead, TableBody, Th, SortableTh, Td, EmptyRow } from '@/components/ui/Table';
import { TableFilterBar, TableSearchInput } from '@/components/ui/TableFilterBar';
import { Badge } from '@/components/ui/Badge';
import { DeleteConfirmDialog } from '@/components/ui/DeleteConfirmDialog';
import { Skeleton, SkeletonRow } from '@/components/ui/Spinner';
import { Pagination } from '@/components/ui/Pagination';
import { ProjectModal } from './ProjectModal';
import { ProjectScheduleDialog } from '@/components/schedules/ProjectScheduleDialog';
import { deleteProject, getProjectDeleteImpact, getProducts } from '@/lib/api';
import { matchesMultiField } from '@/lib/tableFilters';
import { formatDate } from '@/lib/utils';
import { useNotifications } from '@/hooks/useNotifications';
import { getApiErrorMessage } from '@/lib/notifications';
import { useTableSort } from '@/hooks/useTableSort';
import { usePagination } from '@/hooks/usePagination';
import { useViewMode } from '@/hooks/useViewMode';
import {
  invalidateDashboardTiles,
  invalidateProjectLists,
  invalidateRunLists,
  invalidateSbomLists,
  invalidateScheduleLists,
} from '@/lib/queryInvalidation';
import type { ProductListResponse, Project } from '@/types';

type ProjectSortKey = 'id' | 'project_name' | 'project_status' | 'created_by' | 'created_on';


/**
 * Row actions, shared by both views so the grid can never drift into offering
 * a different set of operations than the list.
 */
function ProjectRowActions({
  project,
  onSchedule,
  onEdit,
  onDelete, onSelect,
}: {
  onSelect?: (project: Project) => void;
  project: Project;
  onSchedule: (project: Project) => void;
  onEdit: (project: Project) => void;
  onDelete: (project: Project) => void;
}) {
  return <InventoryActionMenu label={`Actions for project ${project.project_name}`} actions={[
    { label: 'View project', ...(onSelect ? { onClick: () => onSelect(project) } : { href: `/projects?project=${project.id}` }) },
    { label: 'Edit project', accessibleName: `Edit ${project.project_name}`, onClick: () => onEdit(project) },
    { label: 'Schedule', accessibleName: `Configure periodic analysis schedule for ${project.project_name}`, onClick: () => onSchedule(project) },
    { label: 'Notification settings', href: `/settings/notifications?scope=PROJECT&target=${project.id}` },
    { label: 'Delete project', accessibleName: `Delete ${project.project_name}`, onClick: () => onDelete(project), destructive: true },
  ]} />;
}

/** One project as a card. Same fields as a list row, laid out vertically. */
function ProjectCard({
  project,
  onSchedule,
  onEdit,
  onDelete, selected, onSelect,
}: {
  selected?: boolean; onSelect?: (project: Project) => void;
  project: Project;
  onSchedule: (project: Project) => void;
  onEdit: (project: Project) => void;
  onDelete: (project: Project) => void;
}) {
  const inventory = useQuery<ProductListResponse>({ queryKey: ['products', project.id], queryFn: ({ signal }) => getProducts(project.id, signal), enabled: false });
  const appCount = inventory.data?.total;
  const sbomCount = project.sbom_count ?? (inventory.data ? inventory.data.items.reduce((sum, app) => sum + (app.sbom_count ?? 0), 0) : undefined);
  return (
    <div className={`relative flex min-w-0 flex-col rounded-xl border p-4 shadow-card transition-colors ${selected ? 'border-hcl-blue bg-blue-50/40' : 'border-hcl-border bg-surface hover:border-hcl-blue/40'}`}>
      {onSelect && <button type="button" aria-label={`Select project ${project.project_name}`} aria-pressed={Boolean(selected)} onClick={() => onSelect(project)} className="absolute inset-0 z-0 rounded-xl focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/50" />}
      <div className="pointer-events-none relative flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="font-mono text-[11px] text-hcl-muted">#{project.id}</p>
          <h3 className="mt-0.5 truncate font-semibold text-hcl-navy" title={project.project_name}>
            {project.project_name}
          </h3>
        </div>
        <Badge variant={project.project_status === 1 ? 'success' : 'gray'}>
          {project.project_status === 1 ? 'ACTIVE' : 'INACTIVE'}
        </Badge>
      </div>

      {/* Two clamped lines keeps every card the same height regardless of how
          much detail a project carries. */}
      <p title={project.project_details || undefined} className="pointer-events-none relative mt-2 line-clamp-2 min-h-[2.5rem] text-xs text-hcl-muted">
        {project.project_details || 'No details provided.'}
      </p>

      <div className="pointer-events-none relative mt-3 flex flex-wrap gap-3 text-xs text-hcl-navy">{appCount !== undefined && <span>{appCount} {appCount === 1 ? 'Application' : 'Applications'}</span>}{sbomCount !== undefined && <span>{sbomCount} {sbomCount === 1 ? 'SBOM' : 'SBOMs'}</span>}</div>
      <dl className="pointer-events-none relative mt-3 space-y-1 text-xs">
        <div className="flex gap-1.5">
          <dt className="text-hcl-muted">Created by</dt>
          <dd className="min-w-0 truncate text-hcl-navy">{project.created_by || '—'}</dd>
        </div>
        <div className="flex gap-1.5">
          <dt className="text-hcl-muted">Created on</dt>
          <dd className="whitespace-nowrap text-hcl-navy">{formatDate(project.created_on)}</dd>
        </div>
      </dl>

      <div className="relative mt-3 flex items-center justify-between border-t border-hcl-border pt-2"><span className="pointer-events-none text-xs font-medium text-hcl-blue">{selected ? 'Selected' : ''}</span>
        <ProjectRowActions
          project={project}
          onSchedule={onSchedule}
          onEdit={onEdit}
          onDelete={onDelete}
          onSelect={onSelect}
        />
      </div>
    </div>
  );
}

interface ProjectsTableProps {
  projects: Project[] | undefined;
  isLoading: boolean;
  error: Error | null;
  initialProjectId?: number | null;
  selectedId?: number | null;
  onSelect?: (project: Project) => void;
  onVisibleIdsChange?: (ids: number[]) => void;
  onCreate?: () => void;
}

export function ProjectsTable({ projects, isLoading, error, initialProjectId, selectedId, onSelect, onVisibleIdsChange, onCreate }: ProjectsTableProps) {
  const queryClient = useQueryClient();
  const { showSuccess, showError } = useNotifications();
  const [editProject, setEditProject] = useState<Project | null>(null);
  const [scheduleProject, setScheduleProject] = useState<Project | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Project | null>(null);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'inactive'>('all');
  const [viewMode, setViewMode] = useViewMode('projects', onSelect ? 'grid' : 'list');

  // Pre-flight cascade impact, fetched only while the dialog is open.
  const impactQuery = useQuery({
    queryKey: ['project-delete-impact', deleteTarget?.id],
    queryFn: ({ signal }) => getProjectDeleteImpact(deleteTarget!.id, signal),
    enabled: deleteTarget !== null,
    staleTime: 0,
  });

  const deleteMutation = useMutation({
    mutationFn: ({ id, permanent }: { id: number; permanent: boolean }) =>
      deleteProject(id, { permanent }),
    onSuccess: (_data, { permanent }) => {
      // Project delete cascades to its SBOMs (and their runs/schedules);
      // refresh every affected list view so the UI matches the cascade.
      invalidateProjectLists(queryClient);
      invalidateSbomLists(queryClient);
      invalidateRunLists(queryClient);
      invalidateScheduleLists(queryClient);
      invalidateDashboardTiles(queryClient);
      const name = deleteTarget?.project_name ?? 'Project';
      showSuccess(permanent
        ? `Project “${name}” was deleted successfully.`
        : `Project “${name}” was archived successfully.`);
      setDeleteTarget(null);
    },
    onError: (error: unknown) => {
      showError(getApiErrorMessage(error, 'Project deletion failed. Please try again.'));
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

  const sortAccessors = useMemo(
    () => ({
      id: (p: Project) => p.id,
      project_name: (p: Project) => (p.project_name ?? '').toLowerCase(),
      project_status: (p: Project) => (p.project_status === 1 ? 1 : 0),
      created_by: (p: Project) => (p.created_by ?? '').toLowerCase(),
      created_on: (p: Project) => p.created_on ?? '',
    }),
    [],
  );

  const { sort, sortedRows, toggle: toggleSort } = useTableSort<Project, ProjectSortKey>(
    filteredProjects,
    sortAccessors,
    { initialKey: 'id', initialDirection: 'desc' },
  );

  const pagination = usePagination<Project>(sortedRows, {
    defaultPageSize: 25,
    storageKey: 'projects',
  });

  useEffect(() => {
    pagination.resetPage();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search, statusFilter]);

  const positionedProject = useRef<number | null | undefined>(undefined);
  useEffect(() => {
    if (isLoading || error) return;
    if (initialProjectId !== positionedProject.current) {
      const index = sortedRows.findIndex(project => project.id === initialProjectId);
      const targetPage = index < 0 ? pagination.page : Math.floor(index / pagination.pageSize) + 1;
      if (targetPage !== pagination.page) { pagination.setPage(targetPage); return; }
      positionedProject.current = initialProjectId;
    }
    onVisibleIdsChange?.(pagination.pageItems.map(project => project.id));
    // Pagination setters are recreated by the existing hook; depend on its values.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialProjectId, sortedRows, pagination.page, pagination.pageSize, pagination.pageItems, isLoading, error, onVisibleIdsChange]);

  if (error) {
    return (
      <Alert variant="error" title="Could not load projects">
        {getApiErrorMessage(error, 'Projects could not be loaded. Please try again.')}
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
              placeholder="Search projects…"
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
            <ViewToggle value={viewMode} onChange={setViewMode} label="projects" />
          </TableFilterBar>
        ) : null}

        {viewMode === 'grid' ? (
          <div className="p-4">
            {isLoading ? (
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
                {Array.from({ length: 6 }).map((_, i) => (
                  <div key={i} className="rounded-xl border border-hcl-border bg-surface p-4">
                    <Skeleton className="h-3 w-10" />
                    <Skeleton className="mt-2 h-4 w-40" />
                    <Skeleton className="mt-3 h-8 w-full" />
                    <Skeleton className="mt-3 h-3 w-32" />
                  </div>
                ))}
              </div>
            ) : !projects?.length ? (
              <p className="py-10 text-center text-sm text-hcl-muted">
                No projects yet. Projects organize applications and their SBOMs.
                {onCreate && <button className="mt-3 block w-full font-medium text-hcl-blue" onClick={onCreate}>Create Project</button>}
              </p>
            ) : !filteredProjects.length ? (
              <p className="py-10 text-center text-sm text-hcl-muted">
                No projects match your filters.
                <button className="mt-3 block w-full font-medium text-hcl-blue" onClick={clearFilters}>Clear filters</button>
              </p>
            ) : (
              /* Same paginated, filtered, sorted slice the list renders — the
                 toggle changes presentation only, never which rows you see. */
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
                {pagination.pageItems.map((project) => (
                  <ProjectCard
                    key={project.id}
                    project={project}
                    selected={selectedId === project.id}
                    onSelect={onSelect}
                    onSchedule={setScheduleProject}
                    onEdit={setEditProject}
                    onDelete={setDeleteTarget}
                  />
                ))}
              </div>
            )}
          </div>
        ) : (
          <Table striped ariaLabel="Projects table">
            <TableHead>
              <tr>
                <SortableTh
                  sortKey="id"
                  activeKey={sort.key}
                  direction={sort.direction}
                  onToggle={(k) => toggleSort(k as ProjectSortKey)}
                >
                  ID
                </SortableTh>
                <SortableTh
                  sortKey="project_name"
                  activeKey={sort.key}
                  direction={sort.direction}
                  onToggle={(k) => toggleSort(k as ProjectSortKey)}
                >
                  Name
                </SortableTh>
                <SortableTh
                  sortKey="project_status"
                  activeKey={sort.key}
                  direction={sort.direction}
                  onToggle={(k) => toggleSort(k as ProjectSortKey)}
                >
                  Status
                </SortableTh>
                <Th>Details</Th>
                <SortableTh
                  sortKey="created_by"
                  activeKey={sort.key}
                  direction={sort.direction}
                  onToggle={(k) => toggleSort(k as ProjectSortKey)}
                >
                  Created By
                </SortableTh>
                <SortableTh
                  sortKey="created_on"
                  activeKey={sort.key}
                  direction={sort.direction}
                  onToggle={(k) => toggleSort(k as ProjectSortKey)}
                >
                  Created On
                </SortableTh>
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
                pagination.pageItems.map((project) => (
                  <tr key={project.id} className={`transition-colors hover:bg-hcl-light/40 ${selectedId === project.id ? 'bg-blue-50/60' : ''}`}>
                    <Td className="font-mono text-xs text-hcl-muted">#{project.id}</Td>
                    <Td className="font-medium text-hcl-navy">{onSelect ? <button aria-label={`Select project ${project.project_name}`} aria-pressed={selectedId === project.id} className="rounded text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/50" onClick={() => onSelect(project)}>{project.project_name}{selectedId === project.id && <span className="ml-2 text-xs text-hcl-blue">Selected</span>}</button> : project.project_name}</Td>
                    <Td>
                      <Badge variant={project.project_status === 1 ? 'success' : 'gray'}>
                        {project.project_status === 1 ? 'ACTIVE' : 'INACTIVE'}
                      </Badge>
                    </Td>
                    <Td className="max-w-xs truncate text-hcl-muted">
                      {project.project_details || '—'}
                    </Td>
                    <Td className="text-hcl-muted">{project.created_by || '—'}</Td>
                    <Td className="whitespace-nowrap text-hcl-muted">{formatDate(project.created_on)}</Td>
                    <Td className="text-right">
                      <ProjectRowActions
                        project={project}
                        onSchedule={setScheduleProject}
                        onEdit={setEditProject}
                        onDelete={setDeleteTarget}
                        onSelect={onSelect}
                      />
                    </Td>
                  </tr>
                ))
              )}
            </TableBody>
          </Table>
        )}

        {!isLoading && filteredProjects.length > 0 ? (
          <Pagination
            page={pagination.page}
            pageSize={pagination.pageSize}
            total={pagination.total}
            totalPages={pagination.totalPages}
            rangeStart={pagination.rangeStart}
            rangeEnd={pagination.rangeEnd}
            hasPrev={pagination.hasPrev}
            hasNext={pagination.hasNext}
            onPageChange={pagination.setPage}
            onPageSizeChange={pagination.setPageSize}
            itemNoun="project"
          />
        ) : null}
      </div>

      {editProject && (
        <ProjectModal
          open={!!editProject}
          onClose={() => setEditProject(null)}
          project={editProject}
        />
      )}

      {scheduleProject && (
        <ProjectScheduleDialog
          open={!!scheduleProject}
          onClose={() => setScheduleProject(null)}
          project={scheduleProject}
        />
      )}

      <DeleteConfirmDialog
        title={`Delete project “${deleteTarget?.project_name ?? ''}”?`}
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        onConfirm={({ permanent }) =>
          deleteTarget && deleteMutation.mutate({ id: deleteTarget.id, permanent })
        }
        loading={deleteMutation.isPending}
        recordName={deleteTarget?.project_name ?? ''}
        recordKind="project"
        cascadeImpact={
          impactQuery.data
            ? [
                { label: 'SBOM', count: impactQuery.data.sboms },
                { label: 'run', count: impactQuery.data.runs },
                { label: 'finding', count: impactQuery.data.findings },
                { label: 'schedule', count: impactQuery.data.schedules },
              ]
            : []
        }
      />
    </>
  );
}
