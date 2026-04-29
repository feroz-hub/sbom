'use client';

import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Eye, Trash2 } from 'lucide-react';
import { useRouter } from 'next/navigation';
import { Alert } from '@/components/ui/Alert';
import { Select } from '@/components/ui/Select';
import { Table, TableHead, TableBody, Th, SortableTh, Td, EmptyRow } from '@/components/ui/Table';
import { TableFilterBar, TableSearchInput } from '@/components/ui/TableFilterBar';
import { ConfirmDialog } from '@/components/ui/Dialog';
import { SkeletonRow } from '@/components/ui/Spinner';
import { Pagination } from '@/components/ui/Pagination';
import { SbomStatusBadge } from '@/components/sboms/SbomStatusBadge';
import { deleteSbom } from '@/lib/api';
import { matchesMultiField } from '@/lib/tableFilters';
import { formatDate } from '@/lib/utils';
import { useToast } from '@/hooks/useToast';
import { useTableSort } from '@/hooks/useTableSort';
import { usePagination } from '@/hooks/usePagination';
import { sbomAnalysisShortLabel } from '@/lib/analysisRunStatusLabels';
import type { AnalysisStatus } from '@/hooks/useBackgroundAnalysis';
import type { SBOMSource } from '@/types';

type SbomSortKey = 'id' | 'sbom_name' | 'project' | 'created_by' | 'created_on';

interface SbomsTableProps {
  sboms: SBOMSource[] | undefined;
  isLoading: boolean;
  error: Error | null;
}

function displayProject(sb: SBOMSource): string {
  if (sb.project_name?.trim()) return sb.project_name.trim();
  if (sb.projectid != null) return `Project #${sb.projectid}`;
  return 'Unassigned';
}

function normalizeAnalysis(sb: SBOMSource): AnalysisStatus {
  return sb._analysisStatus ?? 'NOT_ANALYSED';
}

const ANALYSIS_OPTIONS: { value: string; label: string }[] = [
  { value: '', label: 'All analysis states' },
  { value: 'NOT_ANALYSED', label: 'Not scanned' },
  { value: 'ANALYSING', label: 'Scanning…' },
  { value: 'PASS', label: sbomAnalysisShortLabel('PASS') },
  { value: 'FAIL', label: sbomAnalysisShortLabel('FAIL') },
  { value: 'PARTIAL', label: sbomAnalysisShortLabel('PARTIAL') },
  { value: 'ERROR', label: sbomAnalysisShortLabel('ERROR') },
];

export function SbomsTable({ sboms, isLoading, error }: SbomsTableProps) {
  const router = useRouter();
  const queryClient = useQueryClient();
  const { showToast } = useToast();
  const [deleteTarget, setDeleteTarget] = useState<SBOMSource | null>(null);
  const [search, setSearch] = useState('');
  const [projectFilter, setProjectFilter] = useState('');
  const [analysisFilter, setAnalysisFilter] = useState('');

  const deleteMutation = useMutation({
    mutationFn: (sbom: SBOMSource) => deleteSbom(sbom.id, sbom.created_by ?? ''),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sboms'] });
      showToast('SBOM deleted successfully', 'success');
      setDeleteTarget(null);
    },
    onError: (err: Error) => {
      showToast(`Delete failed: ${err.message}`, 'error');
    },
  });

  const projectOptions = useMemo(() => {
    const set = new Set<string>();
    sboms?.forEach((sb) => set.add(displayProject(sb)));
    return Array.from(set).sort((a, b) => a.localeCompare(b));
  }, [sboms]);

  const filteredSboms = useMemo(() => {
    if (!sboms?.length) return [];
    let rows = sboms;
    if (search.trim()) {
      rows = rows.filter((sb) =>
        matchesMultiField(search, [
          String(sb.id),
          sb.sbom_name,
          displayProject(sb),
          sb.sbom_version,
          sb.productver,
          String(sb.sbom_type ?? ''),
          sb.created_by,
          formatDate(sb.created_on),
        ]),
      );
    }
    if (projectFilter) {
      rows = rows.filter((sb) => displayProject(sb) === projectFilter);
    }
    if (analysisFilter) {
      rows = rows.filter((sb) => normalizeAnalysis(sb) === analysisFilter);
    }
    return rows;
  }, [sboms, search, projectFilter, analysisFilter]);

  const filtersActive = Boolean(search.trim() || projectFilter || analysisFilter);
  const clearFilters = () => {
    setSearch('');
    setProjectFilter('');
    setAnalysisFilter('');
  };

  const sortAccessors = useMemo(
    () => ({
      id: (sb: SBOMSource) => sb.id,
      sbom_name: (sb: SBOMSource) => (sb.sbom_name ?? '').toLowerCase(),
      project: (sb: SBOMSource) => displayProject(sb).toLowerCase(),
      created_by: (sb: SBOMSource) => (sb.created_by ?? '').toLowerCase(),
      created_on: (sb: SBOMSource) => sb.created_on ?? '',
    }),
    [],
  );

  const { sort, sortedRows, toggle: toggleSort } = useTableSort<SBOMSource, SbomSortKey>(
    filteredSboms,
    sortAccessors,
    { initialKey: 'id', initialDirection: 'desc' },
  );

  const pagination = usePagination<SBOMSource>(sortedRows, {
    defaultPageSize: 25,
    storageKey: 'sboms',
  });

  useEffect(() => {
    pagination.resetPage();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search, projectFilter, analysisFilter]);

  if (error) {
    return (
      <Alert variant="error" title="Could not load SBOMs">
        {error.message}
      </Alert>
    );
  }

  const total = sboms?.length ?? 0;
  const shown = filteredSboms.length;

  return (
    <>
      <div className="overflow-hidden rounded-xl border border-hcl-border bg-surface shadow-card">
        {!isLoading && total > 0 ? (
          <TableFilterBar
            onClear={clearFilters}
            clearDisabled={!filtersActive}
            resultHint={
              filtersActive ? `Showing ${shown} of ${total}` : `${total} SBOM${total === 1 ? '' : 's'}`
            }
          >
            <TableSearchInput
              value={search}
              onChange={setSearch}
              placeholder="Name, ID, project, format, author…"
              label="Search"
            />
            <div className="w-full min-w-[10rem] sm:w-48">
              <Select
                label="Project"
                value={projectFilter}
                onChange={(e) => setProjectFilter(e.target.value)}
                className="w-full"
              >
                <option value="">All projects</option>
                {projectOptions.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </Select>
            </div>
            <div className="w-full min-w-[10rem] sm:w-52">
              <Select
                label="Analysis"
                value={analysisFilter}
                onChange={(e) => setAnalysisFilter(e.target.value)}
                className="w-full"
              >
                {ANALYSIS_OPTIONS.map(({ value, label }) => (
                  <option key={value || '__all-analysis__'} value={value}>
                    {label}
                  </option>
                ))}
              </Select>
            </div>
          </TableFilterBar>
        ) : null}

        <Table striped>
          <TableHead>
            <tr>
              <SortableTh
                sortKey="id"
                activeKey={sort.key}
                direction={sort.direction}
                onToggle={(k) => toggleSort(k as SbomSortKey)}
              >
                ID
              </SortableTh>
              <SortableTh
                sortKey="sbom_name"
                activeKey={sort.key}
                direction={sort.direction}
                onToggle={(k) => toggleSort(k as SbomSortKey)}
              >
                Name
              </SortableTh>
              <SortableTh
                sortKey="project"
                activeKey={sort.key}
                direction={sort.direction}
                onToggle={(k) => toggleSort(k as SbomSortKey)}
              >
                Project
              </SortableTh>
              <Th>Version</Th>
              <Th>Format</Th>
              <Th>Analysis</Th>
              <SortableTh
                sortKey="created_by"
                activeKey={sort.key}
                direction={sort.direction}
                onToggle={(k) => toggleSort(k as SbomSortKey)}
              >
                Created By
              </SortableTh>
              <SortableTh
                sortKey="created_on"
                activeKey={sort.key}
                direction={sort.direction}
                onToggle={(k) => toggleSort(k as SbomSortKey)}
              >
                Created On
              </SortableTh>
              <Th className="text-right">Actions</Th>
            </tr>
          </TableHead>
          <TableBody>
            {isLoading ? (
              Array.from({ length: 5 }).map((_, i) => <SkeletonRow key={i} cols={9} />)
            ) : !sboms?.length ? (
              <EmptyRow cols={9} message="No SBOMs found. Upload your first SBOM!" />
            ) : !filteredSboms.length ? (
              <EmptyRow
                cols={9}
                message="No SBOMs match your filters. Try adjusting search or clear filters."
              />
            ) : (
              pagination.pageItems.map((sbom) => (
                <tr key={sbom.id} className="transition-colors hover:bg-hcl-light/40">
                  <Td className="font-mono text-xs text-hcl-muted">#{sbom.id}</Td>
                  <Td className="max-w-[200px] truncate font-medium text-hcl-navy">{sbom.sbom_name}</Td>
                  <Td className="text-hcl-muted">{displayProject(sbom)}</Td>
                  <Td className="text-hcl-muted">{sbom.sbom_version || sbom.productver || '—'}</Td>
                  <Td className="text-hcl-muted">{sbom.sbom_type || '—'}</Td>
                  <Td>
                    <SbomStatusBadge
                      sbomId={sbom.id}
                      initialStatus={sbom._analysisStatus}
                      initialFindings={sbom._findingsCount}
                    />
                  </Td>
                  <Td className="text-hcl-muted">{sbom.created_by || '—'}</Td>
                  <Td className="whitespace-nowrap text-hcl-muted">{formatDate(sbom.created_on)}</Td>
                  <Td className="text-right">
                    <div className="flex items-center justify-end gap-2">
                      <button
                        onClick={() => router.push(`/sboms/${sbom.id}`)}
                        className="rounded-lg p-1.5 text-hcl-muted transition-colors hover:bg-hcl-light hover:text-hcl-blue"
                        aria-label="View SBOM"
                      >
                        <Eye className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => setDeleteTarget(sbom)}
                        className="rounded-lg p-1.5 text-hcl-muted transition-colors hover:bg-red-50 hover:text-red-600 dark:hover:bg-red-950/40"
                        aria-label="Delete SBOM"
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

        {!isLoading && filteredSboms.length > 0 ? (
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
            itemNoun="SBOM"
          />
        ) : null}
      </div>

      <ConfirmDialog
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        onConfirm={() => deleteTarget && deleteMutation.mutate(deleteTarget)}
        title="Delete SBOM"
        message={`Are you sure you want to delete "${deleteTarget?.sbom_name}"? This action cannot be undone.`}
        confirmLabel="Delete SBOM"
        loading={deleteMutation.isPending}
      />
    </>
  );
}
