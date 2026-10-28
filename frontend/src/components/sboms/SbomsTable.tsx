'use client';

import { RecordIdDisplay, recordIdLabel } from '@/components/ui/RecordIdDisplay';
import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { FileSpreadsheet, SlidersHorizontal, X } from 'lucide-react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { Alert } from '@/components/ui/Alert';
import { Select } from '@/components/ui/Select';
import { PermissionButton as Button } from '@/components/ui/PermissionButton';
import { Table, TableHead, TableBody, Th, SortableTh, Td, EmptyRow } from '@/components/ui/Table';
import { TableSearchInput } from '@/components/ui/TableFilterBar';
import { InventoryActionMenu } from '@/components/projects/InventoryActionMenu';
import { ViewToggle } from '@/components/ui/ViewToggle';
import { useViewMode } from '@/hooks/useViewMode';
import { Button as UiButton } from '@/components/ui/Button';
import styles from './sbom-inventory.module.css';
import { DeleteConfirmDialog } from '@/components/ui/DeleteConfirmDialog';
import { SkeletonRow } from '@/components/ui/Spinner';
import { Pagination } from '@/components/ui/Pagination';
import { SbomLifecycleControls } from './SbomLifecycleControls';
import { sbomEligibility } from '@/lib/sbomEligibility';
import { SbomStatusBadge } from '@/components/sboms/SbomStatusBadge';
import { PinButton } from '@/components/ui/PinButton';
import { SelectionCheckbox } from '@/components/ui/SelectionCheckbox';
import { Fda510kReportDialog } from '@/components/sboms/Fda510kReportDialog';
import { deleteSbom, getSbomDeleteImpact } from '@/lib/api';
import { getApiErrorMessage } from '@/lib/notifications';
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
import { formatSbomFormatLabel } from '@/lib/sbomFormat';
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
  if (sb.projectid != null) return recordIdLabel('Project', sb.project_display_id);
  return 'Unassigned';
}

function displayProduct(sb: SBOMSource): string {
  if (sb.product_name?.trim()) return sb.product_name.trim();
  if (sb.product_id != null) return recordIdLabel('Application', sb.product_display_id);
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


/** Same permission-aware actions in table and card view. */
function SbomRowActions({ sbom, onDelete }: { sbom: SBOMSource; onDelete: (sbom: SBOMSource) => void }) {
  const workspace = canOpenRepairWorkspace(sbom) ? getRepairWorkspaceUrl(sbom) : null;
  return (
    <InventoryActionMenu
      label={`Actions for SBOM ${sbom.sbom_name}`}
      actions={[
        { label: 'View SBOM', href: `/sboms/${sbom.id}` },
        ...(workspace ? [{ label: 'Open Repair Workspace', href: workspace, permission: 'sbom:repair:read' }] : []),
        ...(sbom.logical_sbom_id
          ? [{ label: 'Version history', href: `/sboms/logical/${sbom.logical_sbom_id}` }]
          : []),
        { label: 'Delete SBOM', accessibleName: `Delete ${sbom.sbom_name}`, permission: 'sbom:delete', destructive: true, onClick: () => onDelete(sbom) },
      ]}
    />
  );
}

function SbomCard({
  sbom, selected, onSelect, onDelete, onValidation,
}: {
  sbom: SBOMSource;
  selected: boolean;
  onSelect: (checked: boolean) => void;
  onDelete: (sbom: SBOMSource) => void;
  onValidation: () => void;
}) {
  return (
    <article className={`min-w-0 rounded-xl border bg-surface p-4 shadow-card transition-colors hover:border-hcl-blue/40 ${selected ? 'border-hcl-blue ring-1 ring-hcl-blue/30' : 'border-border'}`}>
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <SelectionCheckbox state={selected ? 'all' : 'none'} onChange={onSelect} label={`Select ${sbom.sbom_name}`} />
          <Link href={`/sboms/${sbom.id}`} className="font-mono text-xs text-hcl-muted hover:text-hcl-blue">
            <RecordIdDisplay displayId={sbom.display_id} />
          </Link>
        </div>
        <SbomRowActions sbom={sbom} onDelete={onDelete} />
      </div>
      <div className="mt-3 flex items-start gap-2">
        <Link href={`/sboms/${sbom.id}`} className="min-w-0 flex-1 break-words text-sm font-semibold leading-6 text-hcl-navy hover:text-hcl-blue hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/30">
          {sbom.sbom_name}
        </Link>
        <PinButton kind="sbom" id={sbom.id} label={sbom.sbom_name} href={`/sboms/${sbom.id}`} compact />
      </div>
      <p className="mt-1 break-words text-xs text-hcl-muted">{displayProject(sbom)} · {displayProduct(sbom)}</p>
      {sbom.logical_sbom_id && (
        <Link className="mt-2 inline-flex text-xs font-medium text-hcl-blue hover:underline" href={`/sboms/logical/${sbom.logical_sbom_id}`}>Version history</Link>
      )}
      <dl className="mt-4 grid grid-cols-2 gap-3 border-t border-border-subtle pt-3 text-xs">
        <div><dt className="text-hcl-muted">SBOM version</dt><dd className="mt-1 font-medium text-hcl-navy">{sbom.sbom_version || '—'}</dd></div>
        <div><dt className="text-hcl-muted">Format</dt><dd className="mt-1 font-medium text-hcl-navy">{formatSbomFormatLabel(sbom.format)}</dd></div>
        <div><dt className="text-hcl-muted">Validation</dt><dd className="mt-1"><button type="button" onClick={onValidation} aria-label={`View validation report for ${sbom.sbom_name}`} className="rounded text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/30"><ValidationCell sbom={sbom} /></button></dd></div>
        <div><dt className="text-hcl-muted">Latest analysis</dt><dd className="mt-1"><SbomStatusBadge sbomId={sbom.id} displayId={sbom.display_id} initialStatus={sbom._analysisStatus} initialFindings={sbom._findingsCount} latestAnalysis={sbom.latest_analysis} /></dd></div>
      </dl>
      <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-border-subtle pt-3">
        <SbomLifecycleControls sbom={sbom} />
        <div className="min-w-0 text-xs text-hcl-muted" title={sbom.created_by ?? undefined}>
          <span className="block max-w-[14rem] truncate">{sbom.created_by || 'Unknown author'}</span>
          <span>{formatDate(sbom.created_on)}</span>
        </div>
      </div>
    </article>
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
  const [selectedIds, setSelectedIds] = useState<Set<string | number>>(() => new Set());
  const [fdaDialogOpen, setFdaDialogOpen] = useState(false);
  const [showFilters, setShowFilters] = useState(false);
  const [viewMode, setViewMode] = useViewMode('sboms-inventory');

  // Keep server and initial hydration deterministic; on first small-screen visit
  // prefer a card layout unless the user already chose a saved view.
  useEffect(() => {
    if (typeof window === 'undefined' || window.innerWidth >= 768) return;
    try {
      if (window.localStorage.getItem('sbom.viewmode.sboms-inventory') === null) {
        setViewMode('grid');
      }
    } catch {
      // Privacy-mode storage restrictions must never block the inventory.
    }
  }, [setViewMode]);

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
      showToast(`SBOM “${sbom.sbom_name}” was ${permanent ? 'deleted' : 'archived'} successfully.`, 'success');
      setDeleteTarget(null);
    },
    onError: (error: unknown) => {
      showToast(getApiErrorMessage(error, 'SBOM deletion failed. Please try again.'), 'error');
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
          String(sb.display_id ?? ''),
          sb.sbom_name,
          displayProject(sb),
          displayProduct(sb),
          sb.sbom_version,
          sb.product_version,
          sb.productver,
          formatSbomFormatLabel(sb.format),
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
  const activeFilterCount = [projectFilter, productFilter, analysisFilter, validationFilter].filter(Boolean).length;
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

  const toggleRowSelection = (sbomId: (string | number), checked: boolean) => {
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

      <section aria-label="SBOM inventory" className="min-w-0 overflow-hidden rounded-xl border border-border bg-surface text-foreground shadow-card">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border-subtle px-4 py-4 sm:px-5">
          <div>
            <h2 className="text-base font-semibold text-hcl-navy">SBOM inventory</h2>
            <p className="mt-0.5 text-xs text-hcl-muted">Review software components, validation and analysis history.</p>
          </div>
          <p className="rounded-full border border-border bg-surface-muted px-3 py-1 text-xs font-medium text-hcl-navy tabular-nums" aria-live="polite">
            {filtersActive ? `${shown} of ${total} SBOMs` : `${total} SBOM${total === 1 ? '' : 's'}`}
          </p>
        </div>
        {!isLoading && total > 0 && (
          <div className="space-y-3 border-b border-border-subtle px-4 py-4 sm:px-5">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
              <TableSearchInput
                id="sbom-inventory-search"
                value={search}
                onChange={setSearch}
                label="Search SBOMs"
                placeholder="Search name, ID, project, product or author"
                className="w-full lg:max-w-md"
              />
              <div className="flex flex-wrap items-center gap-2">
                <UiButton variant="secondary" size="md" aria-expanded={showFilters} aria-controls={showFilters ? "sbom-inventory-filters" : undefined} onClick={() => setShowFilters((value) => !value)}>
                  <SlidersHorizontal className="h-4 w-4" aria-hidden />
                  Filters{activeFilterCount ? ` (${activeFilterCount})` : ''}
                </UiButton>
                <ViewToggle label="SBOMs" value={viewMode} onChange={setViewMode} />
                {viewMode === 'grid' && (
                  <label className="flex items-center gap-2 rounded-lg border border-border px-3 py-2 text-xs text-hcl-navy">
                    <SelectionCheckbox
                      state={selectionState}
                      onChange={toggleAllFiltered}
                      label="Select all filtered SBOMs"
                      disabled={filteredSboms.length === 0}
                    />
                    Select all
                  </label>
                )}
                <Button
                  permission="sbom:export"
                  variant="secondary"
                  size="md"
                  onClick={() => setFdaDialogOpen(true)}
                  disabled={!selectionProjectValid || selectedSboms.some(sbom => !sbomEligibility(sbom).eligible || sbom.analysis_requires_reanalysis)}
                  title={
                    selectedSboms.some(sbom => sbom.lifecycle_status === 'INACTIVE')
                      ? 'Report generation unavailable because a selected SBOM is inactive.'
                      : selectedSboms.length === 0
                        ? 'Select one or more SBOMs'
                        : !selectionProjectValid
                          ? 'Select SBOMs from one assigned project'
                          : 'Export FDA 510(k) SBOM workbook'
                  }
                >
                  <FileSpreadsheet className="h-4 w-4" aria-hidden />
                  FDA report{selectedSboms.length ? ` (${selectedSboms.length})` : ''}
                </Button>
              </div>
            </div>
            {showFilters && (
              <div id="sbom-inventory-filters" className="grid gap-3 rounded-lg border border-border-subtle bg-surface-muted/60 p-3 sm:grid-cols-2 xl:grid-cols-4">
                <Select label="Project" value={projectFilter} onChange={(e) => setProjectFilter(e.target.value)} className="w-full">
                  <option value="">All projects</option>
                  {projectOptions.map((p) => <option key={p} value={p}>{p}</option>)}
                </Select>
                <Select label="Product" value={productFilter} onChange={(e) => setProductFilter(e.target.value)} className="w-full">
                  <option value="">All products</option>
                  {productOptions.map((p) => <option key={p} value={p}>{p}</option>)}
                </Select>
                <Select label="Analysis Status" value={analysisFilter} onChange={(e) => setAnalysisFilter(e.target.value)} className="w-full">
                  {ANALYSIS_OPTIONS.map(({ value, label }) => <option key={value || '__all-analysis__'} value={value}>{label}</option>)}
                </Select>
                <Select label="Upload validation" value={validationFilter} onChange={(e) => setValidationFilter(e.target.value)} className="w-full">
                  {VALIDATION_OPTIONS.map(({ value, label }) => <option key={value || '__all-validation__'} value={value}>{label}</option>)}
                </Select>
              </div>
            )}
            {filtersActive && (
              <div className="flex flex-wrap items-center gap-2 text-xs" aria-label="Active filters">
                {projectFilter && <span className={styles.filterChip}>Project: {projectFilter}<button type="button" aria-label="Remove project filter" onClick={() => setProjectFilter('')}><X className="h-3.5 w-3.5" /></button></span>}
                {productFilter && <span className={styles.filterChip}>Product: {productFilter}<button type="button" aria-label="Remove product filter" onClick={() => setProductFilter('')}><X className="h-3.5 w-3.5" /></button></span>}
                {analysisFilter && <span className={styles.filterChip}>Analysis: {ANALYSIS_OPTIONS.find((item) => item.value === analysisFilter)?.label}<button type="button" aria-label="Remove analysis filter" onClick={() => setAnalysisFilter('')}><X className="h-3.5 w-3.5" /></button></span>}
                {validationFilter && <span className={styles.filterChip}>Validation: {VALIDATION_OPTIONS.find((item) => item.value === validationFilter)?.label}<button type="button" aria-label="Remove validation filter" onClick={() => setValidationFilter('')}><X className="h-3.5 w-3.5" /></button></span>}
                <UiButton size="sm" variant="ghost" onClick={clearFilters}>Clear filters</UiButton>
              </div>
            )}
            {selectedSboms.length > 0 && (
              <div role="status" className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-primary/20 bg-primary-50 px-3 py-2 text-xs text-primary-800 dark:bg-surface-muted dark:text-hcl-navy">
                <span><strong>{selectedSboms.length} selected</strong>{!selectionProjectValid ? ' · Select SBOMs from one project to generate an FDA report.' : ' · Ready for eligible report actions.'}</span>
                <UiButton size="sm" variant="ghost" onClick={() => setSelectedIds(new Set())}>Clear selection</UiButton>
              </div>
            )}
          </div>
        )}
        {viewMode === "list" || isLoading ? (
        <Table striped className={styles.inventoryTable} ariaLabel="SBOM inventory table">
          <TableHead>
            <tr>
              <Th className="w-10" resizable={false}>
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
              <Th>SBOM Format</Th>
              <Th>Validation Status</Th>
              <Th>Analysis Status</Th>
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
              <Th className="text-center">Actions</Th>
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
                  <Td className="font-mono text-xs text-hcl-muted">
                    <Link href={`/sboms/${sbom.id}`} className="rounded hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40">
                      <RecordIdDisplay displayId={sbom.display_id} />
                    </Link>
                  </Td>
                  <Td className="min-w-[210px] max-w-[280px] font-medium text-hcl-navy">
                    <div className="flex min-w-0 items-center gap-1.5">
                      <Link
                        href={`/sboms/${sbom.id}`}
                        title={sbom.sbom_name}
                        className="min-w-0 flex-1 break-words rounded text-sm font-semibold leading-5 text-hcl-navy transition-colors hover:text-hcl-blue hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40"
                      >
                        {sbom.sbom_name}
                      </Link>
                      <PinButton
                        kind="sbom"
                        id={sbom.id}
                        label={sbom.sbom_name}
                        href={`/sboms/${sbom.id}`}
                        compact
                      />
                    </div>
                    {sbom.logical_sbom_id && <Link className="text-xs text-hcl-blue hover:underline" href={`/sboms/logical/${sbom.logical_sbom_id}`}>Version history</Link>}
                  </Td>
	                  <Td className="min-w-[130px] max-w-[185px] text-xs text-hcl-muted"><span className="block break-words">{displayProject(sbom)}</span></Td>
	                  <Td className="min-w-[130px] max-w-[185px] text-xs text-hcl-muted"><span className="block break-words">{displayProduct(sbom)}</span></Td>
	                  <Td className="text-hcl-muted">{sbom.sbom_version || '—'}</Td>
                  <Td className="whitespace-nowrap text-hcl-muted">{formatSbomFormatLabel(sbom.format)}</Td>
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
                      sbomId={sbom.id} displayId={sbom.display_id}
                      initialStatus={sbom._analysisStatus}
                      initialFindings={sbom._findingsCount}
                      latestAnalysis={sbom.latest_analysis}
                    />
                  </Td>
                  <Td className="max-w-[175px]"><span className="block max-w-[165px] truncate text-xs text-hcl-muted" title={sbom.created_by || undefined}>{sbom.created_by || '—'}</span></Td>
                  <Td className="whitespace-nowrap text-hcl-muted">{formatDate(sbom.created_on)}</Td>
                  <Td className="whitespace-nowrap">
                    <div className="flex items-center justify-end gap-2">
                      <SbomLifecycleControls sbom={sbom} />
                      <SbomRowActions sbom={sbom} onDelete={setDeleteTarget} />
                    </div>
                  </Td>
                </tr>
              ))
            )}
          </TableBody>
        </Table>
        ) : (
          <div className="grid gap-4 p-4 sm:grid-cols-2 xl:grid-cols-3" aria-label="SBOM inventory grid">
            {filteredSboms.length === 0 ? (
              <div className="col-span-full rounded-lg border border-dashed border-border p-10 text-center text-sm text-hcl-muted">No SBOMs match the current filters. Clear filters to see your inventory.</div>
            ) : pagination.pageItems.map((sbom) => (
              <SbomCard
                key={sbom.id}
                sbom={sbom}
                selected={selectedIds.has(sbom.id)}
                onSelect={(checked) => toggleRowSelection(sbom.id, checked)}
                onDelete={setDeleteTarget}
                onValidation={() => router.push(`/sboms/${sbom.id}#validation-report`)}
              />
            ))}
          </div>
        )}

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
      </section>

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
