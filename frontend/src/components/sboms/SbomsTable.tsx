'use client';

import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Eye, FileSpreadsheet, Wrench, Trash2 } from 'lucide-react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { Alert } from '@/components/ui/Alert';
import { Select } from '@/components/ui/Select';
import { Button } from '@/components/ui/Button';
import { Table, TableHead, TableBody, Th, SortableTh, Td, EmptyRow } from '@/components/ui/Table';
import { TableFilterBar, TableSearchInput } from '@/components/ui/TableFilterBar';
import { DeleteConfirmDialog } from '@/components/ui/DeleteConfirmDialog';
import { SkeletonRow } from '@/components/ui/Spinner';
import { Pagination } from '@/components/ui/Pagination';
import { SbomStatusBadge } from '@/components/sboms/SbomStatusBadge';
import { PinButton } from '@/components/ui/PinButton';
import { SelectionCheckbox } from '@/components/ui/SelectionCheckbox';
import { Fda510kReportDialog } from '@/components/sboms/Fda510kReportDialog';
import { deleteSbom, getSbomDeleteImpact, HttpError } from '@/lib/api';
import { matchesMultiField } from '@/lib/tableFilters';
import { formatDate } from '@/lib/utils';
import { useToast } from '@/hooks/useToast';
import { useTableSort } from '@/hooks/useTableSort';
import { usePagination } from '@/hooks/usePagination';
import {
  invalidateDashboardTiles,
  invalidateProjectSurfaces,
  invalidateRunLists,
  invalidateScheduleLists,
  invalidateSbomSurfaces,
} from '@/lib/queryInvalidation';
import { stageLabel, validationStatusMeta } from '@/lib/sbomValidation';
import { canOpenRepairWorkspace, getRepairWorkspaceUrl } from '@/lib/repairWorkspace';
import type { AnalysisStatus } from '@/hooks/useBackgroundAnalysis';
import type { SBOMSource, SbomValidationStatus } from '@/types';

type SbomSortKey = 'id' | 'sbom_name' | 'project' | 'product' | 'created_by' | 'created_on';

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

function displayProduct(sb: SBOMSource): string {
  if (sb.product_name?.trim()) return sb.product_name.trim();
  if (sb.product_id != null) return `Product #${sb.product_id}`;
  return 'Unassigned';
}

function normalizeAnalysis(sb: SBOMSource): AnalysisStatus {
  if (sb._analysisStatus) return sb._analysisStatus;
  const latest = sb.latest_analysis;
  if (!latest) return 'NOT_ANALYSED';
  const result = String(latest.result || '').toLowerCase();
  const status = String(latest.status || '').toUpperCase();
  if (result === 'queued' || status === 'PENDING' || status === 'QUEUED') return 'QUEUED';
  if (result === 'running' || status === 'RUNNING' || status === 'ANALYSING') return 'RUNNING';
  if (result === 'interrupted' || status === 'INTERRUPTED') return 'INTERRUPTED';
  if (result === 'cancelled' || result === 'canceled' || status === 'CANCELLED' || status === 'CANCELED') return 'CANCELLED';
  if (result === 'failed' || status === 'ERROR' || status === 'FAILED') return 'ERROR';
  return 'OK';
}

const ANALYSIS_OPTIONS: { value: string; label: string }[] = [
  { value: '', label: 'All analysis states' },
  { value: 'NOT_ANALYSED', label: 'Not Run' },
  { value: 'QUEUED', label: 'Queued' },
  { value: 'RUNNING', label: 'Running' },
  { value: 'OK', label: 'Completed' },
  { value: 'ERROR', label: 'Failed' },
  { value: 'INTERRUPTED', label: 'Interrupted' },
  { value: 'CANCELLED', label: 'Cancelled' },
];

const VALIDATION_OPTIONS: { value: string; label: string }[] = [
  { value: '', label: 'All upload states' },
  { value: 'validated', label: 'Validated' },
  { value: 'validated_warnings', label: 'Validated · with warnings' },
  { value: 'failed', label: 'Validation failed' },
  { value: 'quarantined', label: 'Quarantined' },
];

function ValidationCell({ sbom }: { sbom: SBOMSource }) {
  const status = (sbom.status ?? 'validated') as SbomValidationStatus;
  const warnings = sbom.warning_count ?? 0;
  const errors = sbom.error_count ?? 0;
  const meta = validationStatusMeta(status, warnings);
  const tooltip =
    status === 'failed' || status === 'quarantined'
      ? `${meta.description} Stopped at: ${stageLabel(sbom.failed_stage ?? null)}.`
      : meta.description;
  return (
    <span
      className={`inline-flex max-w-full items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium ${meta.classes}`}
      title={tooltip}
    >
      <span className="min-w-0 truncate">{meta.label}</span>
      {(status === 'failed' || status === 'quarantined') && errors > 0 && (
        <span className="font-bold tabular-nums">{errors}</span>
      )}
    </span>
  );
}

export function SbomsTable({ sboms, isLoading, error }: SbomsTableProps) {
  const router = useRouter();
  const queryClient = useQueryClient();
  const { showToast } = useToast();
  const [deleteTarget, setDeleteTarget] = useState<SBOMSource | null>(null);
  const [search, setSearch] = useState('');
  const [projectFilter, setProjectFilter] = useState('');
  const [productFilter, setProductFilter] = useState('');
  const [analysisFilter, setAnalysisFilter] = useState('');
  const [validationFilter, setValidationFilter] = useState('');
  const [selectedIds, setSelectedIds] = useState<Set<number>>(() => new Set());
  const [fdaDialogOpen, setFdaDialogOpen] = useState(false);

  const impactQuery = useQuery({
    queryKey: ['sbom-delete-impact', deleteTarget?.id],
    queryFn: ({ signal }) => getSbomDeleteImpact(deleteTarget!.id, signal),
    enabled: deleteTarget !== null,
    staleTime: 0,
  });

  const deleteMutation = useMutation({
    mutationFn: ({
      sbom,
      permanent,
    }: {
      sbom: SBOMSource;
      permanent: boolean;
    }) => deleteSbom(sbom.id, sbom.created_by ?? '', { permanent }),
    retry: false,
    onSuccess: (_data, { permanent, sbom }) => {
      invalidateSbomSurfaces(queryClient, sbom.id);
      invalidateProjectSurfaces(queryClient, sbom.projectid);
      invalidateRunLists(queryClient);
      invalidateScheduleLists(queryClient);
      invalidateDashboardTiles(queryClient);
      showToast(
        permanent ? 'SBOM permanently deleted' : 'SBOM soft deleted',
        'success',
      );
      setDeleteTarget(null);
    },
    onError: (err: Error) => {
      const prefix = err instanceof HttpError && err.status === 409
        ? 'Cannot delete SBOM'
        : 'Delete failed';
      showToast(`${prefix}: ${err.message}`, 'error');
    },
  });

  const projectOptions = useMemo(() => {
    const set = new Set<string>();
    sboms?.forEach((sb) => set.add(displayProject(sb)));
    return Array.from(set).sort((a, b) => a.localeCompare(b));
  }, [sboms]);

  const productOptions = useMemo(() => {
    const set = new Set<string>();
    sboms
      ?.filter((sb) => !projectFilter || displayProject(sb) === projectFilter)
      .forEach((sb) => set.add(displayProduct(sb)));
    return Array.from(set).sort((a, b) => a.localeCompare(b));
  }, [sboms, projectFilter]);

  const filteredSboms = useMemo(() => {
    if (!sboms?.length) return [];
    let rows = sboms;
    if (search.trim()) {
      rows = rows.filter((sb) =>
        matchesMultiField(search, [
          String(sb.id),
          sb.sbom_name,
          displayProject(sb),
          displayProduct(sb),
          sb.sbom_version,
          sb.product_version,
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
    if (productFilter) {
      rows = rows.filter((sb) => displayProduct(sb) === productFilter);
    }
    if (analysisFilter) {
      rows = rows.filter((sb) => normalizeAnalysis(sb) === analysisFilter);
    }
    if (validationFilter) {
      rows = rows.filter((sb) => {
        const status = sb.status ?? 'validated';
        const warnings = sb.warning_count ?? 0;
        if (validationFilter === 'validated_warnings') {
          return status === 'validated' && warnings > 0;
        }
        if (validationFilter === 'validated') {
          return status === 'validated' && warnings === 0;
        }
        return status === validationFilter;
      });
    }
    return rows;
  }, [sboms, search, projectFilter, productFilter, analysisFilter, validationFilter]);

  const filtersActive = Boolean(
    search.trim() || projectFilter || productFilter || analysisFilter || validationFilter,
  );
  const clearFilters = () => {
    setSearch('');
    setProjectFilter('');
    setProductFilter('');
    setAnalysisFilter('');
    setValidationFilter('');
  };

  const sortAccessors = useMemo(
    () => ({
      id: (sb: SBOMSource) => sb.id,
      sbom_name: (sb: SBOMSource) => (sb.sbom_name ?? '').toLowerCase(),
      project: (sb: SBOMSource) => displayProject(sb).toLowerCase(),
      product: (sb: SBOMSource) => displayProduct(sb).toLowerCase(),
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

  const selectedSboms = useMemo(
    () => (sboms ?? []).filter((sbom) => selectedIds.has(sbom.id)),
    [sboms, selectedIds],
  );

  const selectedProjectIds = useMemo(
    () => Array.from(new Set(selectedSboms.map((sbom) => sbom.projectid ?? sbom.project_id ?? null))),
    [selectedSboms],
  );
  const selectionProjectValid = selectedSboms.length > 0 && selectedProjectIds.length === 1 && selectedProjectIds[0] !== null;

  const allFilteredSelected = filteredSboms.length > 0 && filteredSboms.every((sbom) => selectedIds.has(sbom.id));
  const someFilteredSelected = filteredSboms.some((sbom) => selectedIds.has(sbom.id));
  const selectionState = allFilteredSelected ? 'all' : someFilteredSelected ? 'some' : 'none';

  const toggleAllFiltered = (checked: boolean) => {
    setSelectedIds((current) => {
      const next = new Set(current);
      for (const sbom of filteredSboms) {
        if (checked) next.add(sbom.id);
        else next.delete(sbom.id);
      }
      return next;
    });
  };

  const toggleRowSelection = (sbomId: number, checked: boolean) => {
    setSelectedIds((current) => {
      const next = new Set(current);
      if (checked) next.add(sbomId);
      else next.delete(sbomId);
      return next;
    });
  };

  const pagination = usePagination<SBOMSource>(sortedRows, {
    defaultPageSize: 25,
    storageKey: 'sboms',
  });

  useEffect(() => {
    pagination.resetPage();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search, projectFilter, productFilter, analysisFilter, validationFilter]);

  useEffect(() => {
    if (productFilter && !productOptions.includes(productFilter)) {
      setProductFilter('');
    }
  }, [productFilter, productOptions]);

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
      <div className="overflow-hidden rounded-xl border border-hcl-border bg-surface text-foreground shadow-card">
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
            <div className="w-full min-w-[10rem] sm:w-48">
              <Select
                label="Product"
                value={productFilter}
                onChange={(e) => setProductFilter(e.target.value)}
                className="w-full"
              >
                <option value="">All products</option>
                {productOptions.map((p) => (
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
            <div className="w-full min-w-[10rem] sm:w-52">
              <Select
                label="Upload validation"
                value={validationFilter}
                onChange={(e) => setValidationFilter(e.target.value)}
                className="w-full"
              >
                {VALIDATION_OPTIONS.map(({ value, label }) => (
                  <option key={value || '__all-validation__'} value={value}>
                    {label}
                  </option>
                ))}
              </Select>
            </div>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setFdaDialogOpen(true)}
              disabled={!selectionProjectValid}
              title={
                selectedSboms.length === 0
                  ? 'Select one or more SBOMs'
                  : !selectionProjectValid
                    ? 'Select SBOMs from one assigned project'
                    : 'Export FDA 510(k) SBOM workbook'
              }
            >
              <FileSpreadsheet className="h-4 w-4" />
              FDA report{selectedSboms.length ? ` (${selectedSboms.length})` : ''}
            </Button>
          </TableFilterBar>
        ) : null}

        <Table striped ariaLabel="SBOM inventory table">
          <TableHead>
            <tr>
              <Th className="w-10">
                <SelectionCheckbox
                  state={selectionState}
                  onChange={toggleAllFiltered}
                  label="Select all filtered SBOMs"
                  disabled={filteredSboms.length === 0}
                />
              </Th>
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
              <SortableTh
                sortKey="product"
                activeKey={sort.key}
                direction={sort.direction}
                onToggle={(k) => toggleSort(k as SbomSortKey)}
              >
                Product
              </SortableTh>
              <Th>Version</Th>
              <Th>Format</Th>
              <Th>Upload</Th>
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
              Array.from({ length: 5 }).map((_, i) => <SkeletonRow key={i} cols={12} />)
            ) : !sboms?.length ? (
              <EmptyRow cols={12} message="No SBOMs found. Upload your first SBOM!" />
            ) : !filteredSboms.length ? (
              <EmptyRow
                cols={12}
                message="No SBOMs match your filters. Try adjusting search or clear filters."
              />
            ) : (
              pagination.pageItems.map((sbom) => (
                <tr key={sbom.id} className="group">
                  <Td>
                    <SelectionCheckbox
                      state={selectedIds.has(sbom.id) ? 'all' : 'none'}
                      onChange={(checked) => toggleRowSelection(sbom.id, checked)}
                      label={`Select ${sbom.sbom_name}`}
                    />
                  </Td>
                  <Td className="font-mono text-xs text-hcl-muted">#{sbom.id}</Td>
                  <Td className="max-w-[220px] font-medium text-hcl-navy">
                    <div className="flex items-center gap-1.5">
                      <Link
                        href={`/sboms/${sbom.id}`}
                        title={sbom.sbom_name}
                        className="min-w-0 flex-1 truncate rounded font-medium text-hcl-navy transition-colors hover:text-hcl-blue hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40"
                      >
                        {sbom.sbom_name}
                      </Link>
                      <PinButton
                        kind="sbom"
                        id={sbom.id}
                        label={sbom.sbom_name}
                        href={`/sboms/${sbom.id}`}
                        compact
                        hoverOnly
                      />
                    </div>
                  </Td>
	                  <Td className="text-hcl-muted">{displayProject(sbom)}</Td>
	                  <Td className="text-hcl-muted">{displayProduct(sbom)}</Td>
	                  <Td className="text-hcl-muted">{sbom.sbom_version || '—'}</Td>
                  <Td className="text-hcl-muted">{sbom.sbom_type || '—'}</Td>
                  <Td>
                    <button
                      type="button"
                      onClick={() => router.push(`/sboms/${sbom.id}#validation-report`)}
                      className="cursor-pointer text-left"
                      aria-label={`View validation report for ${sbom.sbom_name}`}
                    >
                      <ValidationCell sbom={sbom} />
                    </button>
                  </Td>
                  <Td>
                    <SbomStatusBadge
                      sbomId={sbom.id}
                      initialStatus={sbom._analysisStatus}
                      initialFindings={sbom._findingsCount}
                      latestAnalysis={sbom.latest_analysis}
                    />
                  </Td>
                  <Td className="text-hcl-muted">{sbom.created_by || '—'}</Td>
                  <Td className="whitespace-nowrap text-hcl-muted">{formatDate(sbom.created_on)}</Td>
                  <Td className="text-right">
                    <div className="flex items-center justify-end gap-2">
                      {canOpenRepairWorkspace(sbom) && getRepairWorkspaceUrl(sbom) ? (
                        <button
                          onClick={() => router.push(getRepairWorkspaceUrl(sbom)!)}
                          className="inline-flex items-center gap-1.5 rounded-lg px-2 py-1.5 text-xs font-medium text-hcl-muted transition-colors hover:bg-row-hover hover:text-hcl-blue"
                          aria-label="Open Repair Workspace"
                        >
                          <Wrench className="h-4 w-4" />
                          Workspace
                        </button>
                      ) : null}
                      <button
                        onClick={() => router.push(`/sboms/${sbom.id}`)}
                        className="inline-flex items-center gap-1.5 rounded-lg px-2 py-1.5 text-xs font-medium text-hcl-muted transition-colors hover:bg-row-hover hover:text-hcl-blue"
                        aria-label="View SBOM"
                      >
                        <Eye className="h-4 w-4" />
                        View SBOM
                      </button>
                      <button
                        onClick={() => setDeleteTarget(sbom)}
                        className="inline-flex items-center gap-1.5 rounded-lg px-2 py-1.5 text-xs font-medium text-hcl-muted transition-colors hover:bg-red-50 hover:text-red-600 dark:hover:bg-red-950/40 dark:hover:text-red-300"
                        aria-label="Delete SBOM"
                      >
                        <Trash2 className="h-4 w-4" />
                        Delete SBOM
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

      <DeleteConfirmDialog
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        onConfirm={({ permanent }) =>
          deleteTarget && deleteMutation.mutate({ sbom: deleteTarget, permanent })
        }
        loading={deleteMutation.isPending}
        recordName={deleteTarget?.sbom_name ?? ''}
        recordKind="SBOM"
        allowPermanent={impactQuery.data?.can_delete ?? false}
        permanentBlockedReason={
          impactQuery.isError
            ? 'Permanent deletion is unavailable because delete impact could not be loaded.'
            : impactQuery.data && !impactQuery.data.can_delete
              ? impactQuery.data.warnings.join(' ')
              : impactQuery.isLoading
                ? 'Checking permanent-delete dependencies…'
                : undefined
        }
        cascadeImpact={
          impactQuery.data
            ? [
                { label: 'component', count: impactQuery.data.dependent_counts.components },
                { label: 'analysis run', count: impactQuery.data.dependent_counts.analysis_runs },
                { label: 'vulnerability finding', count: impactQuery.data.dependent_counts.vulnerabilities },
                { label: 'validation report', count: impactQuery.data.dependent_counts.validation_reports },
                { label: 'validation session', count: impactQuery.data.dependent_counts.validation_sessions },
                { label: 'VEX document', count: impactQuery.data.dependent_counts.vex_documents },
                { label: 'VEX statement', count: impactQuery.data.dependent_counts.vex_statements },
                { label: 'schedule', count: impactQuery.data.dependent_counts.schedules },
                { label: 'version', count: impactQuery.data.dependent_counts.versions },
                { label: 'derived SBOM', count: impactQuery.data.dependent_counts.derived_sboms },
              ]
            : []
        }
      />
      {fdaDialogOpen ? (
        <Fda510kReportDialog
          open={fdaDialogOpen}
          onClose={() => setFdaDialogOpen(false)}
          sboms={selectedSboms}
        />
      ) : null}
    </>
  );
}
