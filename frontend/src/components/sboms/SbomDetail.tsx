'use client';

import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { useEffect, useMemo, useState } from 'react';
import { Play, ArrowLeft, ExternalLink, Edit2, GitBranch, History, Layers, Download, Check, RefreshCw, Eye, ArrowRight, X } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Dialog, DialogBody } from '@/components/ui/Dialog';
import { StatusBadge } from '@/components/ui/Badge';
import { Input, Textarea } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import { useToast } from '@/hooks/useToast';
import { Table, TableHead, TableBody, Th, SortableTh, Td, EmptyRow } from '@/components/ui/Table';
import { TableFilterBar, TableSearchInput } from '@/components/ui/TableFilterBar';
import { SkeletonRow } from '@/components/ui/Spinner';
import { Pagination } from '@/components/ui/Pagination';
import { AnalysisProgress } from '@/components/analysis/AnalysisProgress';
import { ScheduleCard } from '@/components/schedules/ScheduleCard';
import { SbomConversionCard } from '@/components/sboms/SbomConversionCard';
import { SbomRawViewer } from '@/components/sboms/SbomRawViewer';
import { ValidationReportSection } from '@/components/sboms/ValidationReportSection';
import { 
  getSbomComponents, 
  getSbomDedupeReport,
  getRuns, 
  getSbomInfo, 
  getSbomRiskSummary, 
  getSbomStats,
  getSbomValidationReport,
  editSbom,
  getSbomVersions,
  compareSbomVersions,
  restoreSbomVersion,
  refreshSbomLifecycle,
  refreshComponentLifecycle,
  getLifecycleProviderStatus,
  overrideComponentLifecycle,
  discoverSbomVexDocuments,
  exportSbomLifecycleReportCsv,
  exportSbomLifecycleReportPack,
  exportSbomVexReportCsv,
  exportSbomVexReportJson,
  exportSbomVexReportPack,
  exportSbomVulnerabilityExcel,
  getVexOverrideHistory,
  getSbomVexStatements,
  overrideVexStatement,
  uploadSbomVexDocument,
  getProjects,
  updateSbom,
  createWorkspaceForSbom,
  BASE_URL
} from '@/lib/api';
import { useAnalysisStream } from '@/hooks/useAnalysisStream';
import {
  invalidateAnalysisCompletion,
  invalidateLifecycleOverrideSurfaces,
  invalidateProjectAssignmentSurfaces,
  invalidateSbomVersionSurfaces,
  invalidateVexSurfaces,
} from '@/lib/queryInvalidation';
import { useTableSort } from '@/hooks/useTableSort';
import { usePagination } from '@/hooks/usePagination';
import { formatDate, formatDuration } from '@/lib/utils';
import { canOpenRepairWorkspace, getRepairWorkspaceUrl, repairWorkspaceLabel } from '@/lib/repairWorkspace';
import { formatSbomFormatLabel } from '@/lib/sbomFormat';
import type { SBOMSource, SBOMComponent, AnalysisRun, VexOverrideAuditEntry, VexStatement, VexStatus } from '@/types';

type ComponentSortKey = 'name' | 'version' | 'component_type' | 'license' | 'lifecycle_status';
type RunSortKey = 'id' | 'run_status' | 'total_findings' | 'duration_ms' | 'started_on';
type EvidenceModalState =
  | { kind: 'lifecycle'; component: SBOMComponent }
  | { kind: 'vex'; statement: VexStatement }
  | null;

const VEX_STATUSES: VexStatus[] = ['affected', 'not_affected', 'fixed', 'under_investigation', 'unknown'];

interface SbomDetailProps {
  sbom: SBOMSource;
}

function canonicalLifecycleStatus(status?: string | null) {
  const normalized = (status || 'Unknown').toLowerCase();
  if (normalized === 'active' || normalized === 'supported') return 'Supported';
  if (normalized === 'eol') return 'EOL';
  if (normalized === 'eos') return 'EOS';
  if (normalized === 'eof') return 'EOF';
  if (normalized === 'deprecated') return 'Deprecated';
  if (normalized === 'unsupported' || normalized === 'unmaintained') return 'Unsupported';
  if (normalized === 'eol soon' || normalized === 'nearing eol') return 'EOL Soon';
  return status || 'Unknown';
}

function lifecycleDisplayLabel(status?: string | null, confidence?: string | null) {
  const canonical = canonicalLifecycleStatus(status);
  const lowConfidence = !confidence || confidence === 'Low' || confidence === 'Unknown';
  if (lowConfidence && ['EOL', 'EOS', 'EOF', 'Unsupported'].includes(canonical)) {
    return `Possible ${canonical}`;
  }
  if (lowConfidence && canonical === 'Unknown') {
    return 'Unknown';
  }
  return canonical;
}

function lifecycleBadgeClass(status?: string | null) {
  const canonical = canonicalLifecycleStatus(status);
  if (canonical === 'EOL' || canonical === 'Unsupported') {
    return 'bg-red-50 text-red-700 border-red-200';
  }
  if (canonical === 'EOS' || canonical === 'EOF' || canonical === 'Deprecated' || canonical === 'EOL Soon') {
    return 'bg-amber-50 text-amber-700 border-amber-200';
  }
  if (canonical === 'Supported') {
    return 'bg-emerald-50 text-emerald-700 border-emerald-200';
  }
  return 'bg-gray-50 text-gray-700 border-gray-200';
}

function addMonths(date: Date, months: number) {
  const next = new Date(date);
  const targetMonth = next.getMonth() + months;
  next.setMonth(targetMonth);
  if (next.getMonth() !== ((targetMonth % 12) + 12) % 12) {
    next.setDate(0);
  }
  return next;
}

function parseLifecycleDate(value?: string | null) {
  if (!value) return null;
  const isoDate = value.trim().match(/^(\d{4})-(\d{2})-(\d{2})/);
  const parsed = isoDate
    ? new Date(Number(isoDate[1]), Number(isoDate[2]) - 1, Number(isoDate[3]))
    : new Date(value);
  if (Number.isNaN(parsed.getTime())) return null;
  parsed.setHours(0, 0, 0, 0);
  return parsed;
}

function eolEosStatusForComponent(component: SBOMComponent) {
  const backendStatus = component.eol_eos_status || null;
  if (backendStatus) {
    return {
      status: backendStatus,
      label: component.eol_eos_status_label || 'Unknown / Not Available',
      date: component.eol_eos_date || component.eol_date || component.eos_date || null,
    };
  }

  const dates = [parseLifecycleDate(component.eol_date), parseLifecycleDate(component.eos_date)]
    .filter((value): value is Date => value !== null)
    .sort((a, b) => a.getTime() - b.getTime());
  if (!dates.length) {
    return { status: 'unknown', label: 'Unknown / Not Available', date: null };
  }

  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const lifecycleDate = dates[0];
  if (lifecycleDate < today) {
    return { status: 'expired', label: 'Expired', date: lifecycleDate.toISOString().slice(0, 10) };
  }
  if (lifecycleDate <= addMonths(today, 3)) {
    return { status: 'less_than_3_months', label: 'Less than 3 months', date: lifecycleDate.toISOString().slice(0, 10) };
  }
  if (lifecycleDate > addMonths(today, 6)) {
    return { status: 'more_than_6_months', label: 'More than 6 months', date: lifecycleDate.toISOString().slice(0, 10) };
  }
  return { status: 'unknown', label: 'Unknown / Not Available', date: lifecycleDate.toISOString().slice(0, 10) };
}

function eolEosStatusBadgeClass(status?: string | null) {
  switch (status) {
    case 'expired':
      return 'bg-red-50 text-red-700 border-red-200';
    case 'less_than_3_months':
      return 'bg-yellow-50 text-yellow-700 border-yellow-200';
    case 'more_than_6_months':
      return 'bg-blue-50 text-blue-700 border-blue-200';
    default:
      return 'bg-gray-50 text-gray-700 border-gray-200';
  }
}

function labelize(value?: string | null) {
  return (value || 'Unknown').replace(/_/g, ' ');
}

function jsonSummary(value?: Record<string, unknown> | null) {
  if (!value) return 'No raw evidence stored.';
  try {
    const text = JSON.stringify(value, null, 2);
    return text.length > 900 ? `${text.slice(0, 900)}…` : text;
  } catch {
    return 'Evidence could not be rendered.';
  }
}

function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function canManageEvidenceFromClient() {
  if (typeof window === 'undefined') return true;
  const configured = window.localStorage.getItem('sbom-role') || window.localStorage.getItem('sbom:user-role');
  if (!configured) return true;
  return configured
    .split(/[,\s]+/)
    .map((role) => role.trim().toLowerCase())
    .some((role) => role === 'admin' || role === 'security');
}

export function SbomDetail({ sbom }: SbomDetailProps) {
  const router = useRouter();
  const queryClient = useQueryClient();
  const { showToast } = useToast();
  const { state, startAnalysis, cancel, reset } = useAnalysisStream(sbom.id);
  const [activeTab, setActiveTab] = useState<'overview' | 'components' | 'normalization' | 'versions' | 'runs'>('overview');
  
  // Edit Component State
  const [editingComp, setEditingComp] = useState<SBOMComponent | null>(null);
  const [editName, setEditName] = useState('');
  const [editVersion, setEditVersion] = useState('');
  const [editSupplier, setEditSupplier] = useState('');
  const [editLicense, setEditLicense] = useState('');
  const [editHashes, setEditHashes] = useState('');
  const [editLifecycleStatus, setEditLifecycleStatus] = useState('Supported');
  const [editEosDate, setEditEosDate] = useState('');
  const [editEolDate, setEditEolDate] = useState('');
  const [editEofDate, setEditEofDate] = useState('');
  const [editIsDeprecated, setEditIsDeprecated] = useState(false);
  const [editMaintStatus, setEditMaintStatus] = useState('Supported');
  const [editRecommendedVersion, setEditRecommendedVersion] = useState('');
  const [editOverrideReason, setEditOverrideReason] = useState('');
  const [editEvidenceUrl, setEditEvidenceUrl] = useState('');
  const [isSavingEdit, setIsSavingEdit] = useState(false);
  const [editError, setEditError] = useState('');
  const [isOpeningWorkspace, setIsOpeningWorkspace] = useState(false);
  const [isRefreshingLifecycle, setIsRefreshingLifecycle] = useState(false);
  const [refreshingComponentId, setRefreshingComponentId] = useState<number | null>(null);
  const [lifecycleMessage, setLifecycleMessage] = useState('');
  const [vexDocumentText, setVexDocumentText] = useState('');
  const [vexMessage, setVexMessage] = useState('');
  const [isUploadingVex, setIsUploadingVex] = useState(false);
  const [isDiscoveringVex, setIsDiscoveringVex] = useState(false);
  const [downloadMessage, setDownloadMessage] = useState('');
  const [evidenceModal, setEvidenceModal] = useState<EvidenceModalState>(null);
  const [isVexOverrideOpen, setIsVexOverrideOpen] = useState(false);
  const [vexOverrideComponentId, setVexOverrideComponentId] = useState('');
  const [vexOverrideVulnerability, setVexOverrideVulnerability] = useState('');
  const [vexOverrideStatus, setVexOverrideStatus] = useState<VexStatus>('under_investigation');
  const [vexOverrideJustification, setVexOverrideJustification] = useState('');
  const [vexOverrideImpact, setVexOverrideImpact] = useState('');
  const [vexOverrideAction, setVexOverrideAction] = useState('');
  const [vexOverrideFixedVersion, setVexOverrideFixedVersion] = useState('');
  const [vexOverrideMitigation, setVexOverrideMitigation] = useState('');
  const [vexOverrideEvidenceUrl, setVexOverrideEvidenceUrl] = useState('');
  const [vexOverrideReason, setVexOverrideReason] = useState('');
  const [vexOverrideError, setVexOverrideError] = useState('');
  const [isSavingVexOverride, setIsSavingVexOverride] = useState(false);
  const [vexOverrideHistory, setVexOverrideHistory] = useState<VexOverrideAuditEntry[]>([]);
  const [isLoadingVexHistory, setIsLoadingVexHistory] = useState(false);
  const [canManageEvidence] = useState(canManageEvidenceFromClient);

  // Version Comparison State
  const [selectedVersions, setSelectedVersions] = useState<number[]>([]);
  const [compareData, setCompareData] = useState<any>(null);
  const [isComparing, setIsComparing] = useState(false);
  const [restoreMessage, setRestoreMessage] = useState('');

  // Deduplication State
  const [showDuplicates, setShowDuplicates] = useState(false);
  const [componentSearch, setComponentSearch] = useState('');
  const [debouncedComponentSearch, setDebouncedComponentSearch] = useState('');
  const [componentPage, setComponentPage] = useState(1);
  const [componentPageSize, setComponentPageSize] = useState(25);
  const [isDedupeModalOpen, setIsDedupeModalOpen] = useState(false);

  // Assign/Edit Project/Details State
  const [isAssignModalOpen, setIsAssignModalOpen] = useState(false);
  const [isEditDetailsModalOpen, setIsEditDetailsModalOpen] = useState(false);
  
  // Assign Project Form State
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null);
  const [assignChangeReason, setAssignChangeReason] = useState('');
  const [isSavingAssign, setIsSavingAssign] = useState(false);
  const [assignError, setAssignError] = useState('');

  // Edit Details Form State
  const [detailName, setDetailName] = useState('');
  const [detailProductName, setDetailProductName] = useState('');
  const [detailProductVersion, setDetailProductVersion] = useState('');
  const [detailSbomVersion, setDetailSbomVersion] = useState('');
  const [detailDescription, setDetailDescription] = useState('');
  const [detailProjectId, setDetailProjectId] = useState<number | null>(null);
  const [detailChangeReason, setDetailChangeReason] = useState('');
  const [isSavingDetails, setIsSavingDetails] = useState(false);
  const [detailsError, setDetailsError] = useState('');

  const { data: lifecycleProviderStatus } = useQuery({
    queryKey: ['lifecycle-provider-status'],
    queryFn: ({ signal }) => getLifecycleProviderStatus(signal),
    staleTime: 60_000,
  });

  const lifecycleProvidersDegraded = lifecycleProviderStatus?.overall_status === 'degraded';

  const { data: projects } = useQuery({
    queryKey: ['projects'],
    queryFn: ({ signal }) => getProjects(signal),
  });

  const handleAssignProjectSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProjectId) {
      setAssignError('Please select a project.');
      return;
    }
    setIsSavingAssign(true);
    setAssignError('');
    try {
      await updateSbom(sbom.id, {
        project_id: selectedProjectId,
        change_reason: assignChangeReason || undefined,
      });

      invalidateProjectAssignmentSurfaces(queryClient, {
        sbomId: sbom.id,
        previousProjectId: sbom.projectid,
        nextProjectId: selectedProjectId,
      });

      setIsAssignModalOpen(false);
    } catch (err: any) {
      setAssignError(err.message || 'Failed to update project assignment.');
    } finally {
      setIsSavingAssign(false);
    }
  };

  const handleEditDetailsSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!detailName.trim()) {
      setDetailsError('SBOM Name is required.');
      return;
    }
    setIsSavingDetails(true);
    setDetailsError('');
    try {
      const payload = {
        name: detailName.trim(),
        product_name: detailProductName.trim() || null,
        product_version: detailProductVersion.trim() || null,
        sbom_version: detailSbomVersion.trim() || null,
        description: detailDescription.trim() || null,
        project_id: detailProjectId || null,
        change_reason: detailChangeReason.trim() || undefined,
      };

      await updateSbom(sbom.id, payload);

      invalidateProjectAssignmentSurfaces(queryClient, {
        sbomId: sbom.id,
        previousProjectId: sbom.projectid,
        nextProjectId: detailProjectId,
      });

      setIsEditDetailsModalOpen(false);
    } catch (err: any) {
      setDetailsError(err.message || 'Failed to update details.');
    } finally {
      setIsSavingDetails(false);
    }
  };

  const [compSortKey, setCompSortKey] = useState<ComponentSortKey>('name');
  const [compSortDirection, setCompSortDirection] = useState<'asc' | 'desc'>('asc');

  const toggleCompSort = (key: ComponentSortKey) => {
    if (key === compSortKey) {
      setCompSortDirection((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setCompSortKey(key);
      setCompSortDirection('asc');
    }
    setComponentPage(1);
  };

  const { data: componentList, isLoading: compLoading } = useQuery({
    queryKey: [
      'sbom-components',
      sbom.id,
      showDuplicates,
      componentPage,
      componentPageSize,
      debouncedComponentSearch,
      compSortKey,
      compSortDirection,
    ],
    queryFn: ({ signal }) =>
      getSbomComponents(sbom.id, {
        includeDuplicates: showDuplicates,
        page: componentPage,
        pageSize: componentPageSize,
        search: debouncedComponentSearch || undefined,
        sortBy: compSortKey,
        sortOrder: compSortDirection,
        signal,
      }),
  });

  const { data: canonicalComponentList } = useQuery({
    queryKey: ['sbom-components-canonical', sbom.id],
    queryFn: ({ signal }) =>
      getSbomComponents(sbom.id, {
        includeDuplicates: false,
        page: 1,
        pageSize: 1000,
        signal,
      }),
    staleTime: 60_000,
  });

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setDebouncedComponentSearch(componentSearch.trim());
      setComponentPage(1);
    }, 250);
    return () => window.clearTimeout(timer);
  }, [componentSearch]);

  const { data: dedupeReport } = useQuery({
    queryKey: ['sbom-dedupe-report', sbom.id],
    queryFn: ({ signal }) => getSbomDedupeReport(sbom.id, signal),
    retry: false,
  });

  const { data: runs, isLoading: runsLoading } = useQuery({
    queryKey: ['runs', { sbom_id: sbom.id }],
    queryFn: ({ signal }) => getRuns({ sbom_id: sbom.id }, signal),
    refetchInterval: state.phase === 'done' ? false : undefined,
  });

  // SBOM info card (parsed metadata)
  const { data: info } = useQuery({
    queryKey: ['sbom-info', sbom.id],
    queryFn: ({ signal }) => getSbomInfo(sbom.id, signal),
    retry: false,
  });

  const { data: documentStats } = useQuery({
    queryKey: ['sbom-stats', sbom.id],
    queryFn: ({ signal }) => getSbomStats(sbom.id, signal),
  });

  // 8-stage validation report
  const { data: validationReport } = useQuery({
    queryKey: ['sbom-validation-report', sbom.id],
    queryFn: ({ signal }) => getSbomValidationReport(sbom.id, signal),
    retry: false,
  });

  const {
    data: vexData,
    isLoading: vexLoading,
    isError: vexIsError,
  } = useQuery({
    queryKey: ['sbom-vex', sbom.id],
    queryFn: ({ signal }) => getSbomVexStatements(sbom.id, signal),
    retry: false,
  });

  // Risk summary
  const { data: risk } = useQuery({
    queryKey: ['sbom-risk', sbom.id, runs?.[0]?.id ?? null],
    queryFn: ({ signal }) => getSbomRiskSummary(sbom.id, signal),
    enabled: !!runs && runs.length > 0,
    retry: false,
  });

  // Versions history
  const { data: versions, refetch: refetchVersions } = useQuery({
    queryKey: ['sbom-versions', sbom.id],
    queryFn: ({ signal }) => getSbomVersions(sbom.id, signal),
  });

  // Components table: server-side sort, search, and pagination
  const componentRows = useMemo<SBOMComponent[]>(
    () => canonicalComponentList?.items ?? [],
    [canonicalComponentList],
  );
  const displayedComponents = useMemo<SBOMComponent[]>(
    () => componentList?.items ?? [],
    [componentList],
  );
  const componentTotalPages = Math.max(
    1,
    Math.ceil((componentList?.total_count ?? 0) / componentPageSize),
  );
  const componentRangeStart =
    (componentList?.total_count ?? 0) === 0 ? 0 : (componentPage - 1) * componentPageSize + 1;
  const componentRangeEnd =
    (componentList?.total_count ?? 0) === 0
      ? 0
      : Math.min(componentPage * componentPageSize, componentList?.total_count ?? 0);
  const compSort = { key: compSortKey, direction: compSortDirection };
  const vexStatements = useMemo<VexStatement[]>(() => vexData?.statements ?? [], [vexData]);
  const vexCounts = useMemo(() => {
    return vexStatements.reduce<Record<string, number>>((acc, statement) => {
      const status = statement.status || 'unknown';
      acc[status] = (acc[status] ?? 0) + 1;
      return acc;
    }, {});
  }, [vexStatements]);
  const vulnerabilityOptions = useMemo(
    () => Array.from(new Set(vexStatements.map((statement) => statement.vulnerability_id).filter(Boolean))),
    [vexStatements],
  );
  const selectedOverrideComponent = useMemo(
    () => componentRows.find((component) => String(component.id) === vexOverrideComponentId) ?? null,
    [componentRows, vexOverrideComponentId],
  );
  const staleLifecycleCount = useMemo(
    () => componentRows.filter((component) => component.lifecycle_is_stale).length,
    [componentRows],
  );

  // Analysis runs: same pattern.
  const runRows = useMemo<AnalysisRun[]>(() => runs ?? [], [runs]);
  const runSortAccessors = useMemo(
    () => ({
      id: (r: AnalysisRun) => r.id,
      run_status: (r: AnalysisRun) => r.run_status ?? '',
      total_findings: (r: AnalysisRun) => r.total_findings ?? -1,
      duration_ms: (r: AnalysisRun) => r.duration_ms ?? -1,
      started_on: (r: AnalysisRun) => r.started_on ?? '',
    }),
    [],
  );
  const {
    sort: runSort,
    sortedRows: sortedRuns,
    toggle: toggleRunSort,
  } = useTableSort<AnalysisRun, RunSortKey>(runRows, runSortAccessors, {
    initialKey: 'id',
    initialDirection: 'desc',
  });
  const runPagination = usePagination<AnalysisRun>(sortedRuns, {
    defaultPageSize: 10,
    storageKey: 'sbom-detail-runs',
  });

  useEffect(() => {
    setComponentPage(1);
  }, [showDuplicates]);

  useEffect(() => {
    runPagination.resetPage();
  }, [runs?.length]);

  const handleRunAnalysis = () => {
    startAnalysis({ sources: ['NVD', 'OSV', 'GITHUB', 'VULNDB'] });
  };

  const handleReset = () => {
    if (state.phase === 'done') {
      invalidateAnalysisCompletion(queryClient, { sbomId: sbom.id });
    }
    reset();
  };

  const isAnalyzing = state.phase === 'connecting' || state.phase === 'parsing' || state.phase === 'running';
  const canUseWorkspace = canOpenRepairWorkspace(sbom);
  const repairUrl = canUseWorkspace ? getRepairWorkspaceUrl(sbom) : null;
  const canBackfillWorkspace = canUseWorkspace && !repairUrl && sbom.workspace_available && sbom.workspace_source === 'backfillable';
  const workspaceUnavailableReason =
    !canUseWorkspace && sbom.workspace_available === false
      ? `Repair Workspace unavailable because ${
          sbom.workspace_unavailable_reason || 'original SBOM content is missing for this record.'
        }`
      : null;
  const workspaceStatus = sbom.validation_status ?? sbom.status;
  const workspaceButtonLabel = canBackfillWorkspace ? 'Create/Open Repair Workspace' : repairWorkspaceLabel(workspaceStatus);
  const workspaceDocumentButtonLabel = canBackfillWorkspace ? 'Create/Open Workspace' : 'Open Workspace';
  const formatTypeDisplay = [
    formatSbomFormatLabel(sbom.detected_format || sbom.current_format || sbom.original_format || sbom.format),
    sbom.detected_spec_version || sbom.spec_version,
  ]
    .filter((value) => value && value !== 'Unknown')
    .join(' ')
    || (sbom.sbom_type ? `Type #${sbom.sbom_type}` : '—');

  const handleOpenRepairWorkspace = async () => {
    if (repairUrl) {
      router.push(repairUrl);
      return;
    }
    if (!canBackfillWorkspace) return;
    setIsOpeningWorkspace(true);
    try {
      const workspace = await createWorkspaceForSbom(sbom.id);
      const url = workspace.repair_workspace_url || (workspace.workspace_id ? `/repair/${workspace.workspace_id}` : null);
      if (!url) throw new Error('Workspace was created but no repair URL was returned.');
      showToast('Repair Workspace ready.', 'success');
      router.push(url);
    } catch (err: any) {
      showToast(err?.message || 'Failed to create Repair Workspace.', 'error');
    } finally {
      setIsOpeningWorkspace(false);
    }
  };

  // Handle opening edit modal
  const openEditModal = (c: SBOMComponent) => {
    setEditingComp(c);
    setEditName(c.name || '');
    setEditVersion(c.version || '');
    setEditSupplier(c.supplier || '');
    setEditLicense(c.license || '');
    setEditHashes(c.hashes || '');
    setEditLifecycleStatus(canonicalLifecycleStatus(c.lifecycle_status));
    setEditEosDate(c.eos_date || '');
    setEditEolDate(c.eol_date || '');
    setEditEofDate(c.eof_date || '');
    setEditIsDeprecated(Boolean(c.deprecated || c.is_deprecated));
    setEditMaintStatus(c.maintenance_status || 'Supported');
    setEditRecommendedVersion(c.recommended_version || '');
    setEditOverrideReason('');
    setEditEvidenceUrl(c.lifecycle_source_url || '');
    setEditError('');
  };

  // Handle saving edit
  const saveComponentEdits = async () => {
    if (!editingComp) return;
    setIsSavingEdit(true);
    setEditError('');
    const payload = {
      lifecycle_status: editLifecycleStatus,
      eos_date: editEosDate || null,
      eol_date: editEolDate || null,
      eof_date: editEofDate || null,
      deprecated: editIsDeprecated,
      is_deprecated: editIsDeprecated,
      maintenance_status: editMaintStatus,
      recommended_version: editRecommendedVersion || null,
      evidence_url: editEvidenceUrl || null,
      reason: editOverrideReason || null,
      updated_by: sbom.created_by ?? null,
    };
    try {
      await overrideComponentLifecycle(editingComp.id, payload);
      showToast('Manual override saved successfully.', 'success');
      setEditingComp(null);

      // Invalidate queries asynchronously (do not block modal closure)
      (async () => {
        try {
          await invalidateLifecycleOverrideSurfaces(queryClient, sbom.id);
        } catch (err) {
          console.error('Failed to invalidate queries:', err);
        }
      })();
    } catch (err: any) {
      console.log('Error saving manual lifecycle override:', {
        endpoint: `/api/components/${editingComp.id}/lifecycle-override`,
        payload,
        error: err
      });
      if (err.name === 'AbortError' || (err.message && err.message.toLowerCase().includes('timeout'))) {
        setEditError('Save took too long. Please check backend logs.');
      } else if (err.status === 400 || err.status === 422) {
        setEditError(`Validation Error: ${err.message}`);
      } else if (err.status === 404) {
        setEditError('Component not found. It may have been removed or renamed.');
      } else if (err.status === 500) {
        setEditError(`Backend Error: ${err.message}`);
      } else {
        setEditError(err.message || 'Failed to save override.');
      }
    } finally {
      setIsSavingEdit(false);
    }
  };

  // Handle checkbox select for version comparison
  const handleSelectVersion = (versionId: number) => {
    setSelectedVersions(prev => {
      if (prev.includes(versionId)) {
        return prev.filter(id => id !== versionId);
      }
      if (prev.length >= 2) {
        // limit to 2
        return [prev[1], versionId];
      }
      return [...prev, versionId];
    });
  };

  // Perform version comparison
  const handleCompare = async () => {
    if (selectedVersions.length !== 2) return;
    setIsComparing(true);
    setCompareData(null);
    try {
      // Sort so A is earlier than B (using index or database order)
      const sorted = [...selectedVersions].sort((a, b) => a - b);
      const res = await compareSbomVersions(sorted[0], sorted[1]);
      setCompareData(res);
    } catch (err: any) {
      console.error(err);
    } finally {
      setIsComparing(false);
    }
  };

  // Restore previous version
  const handleRestore = async (versionId: number) => {
    setRestoreMessage('');
    try {
      const restoredVersion = await restoreSbomVersion(sbom.id, versionId, sbom.created_by ?? undefined);
      setRestoreMessage('Version restored successfully as new HEAD! Refreshing...');
      invalidateSbomVersionSurfaces(queryClient, sbom.id);
      setTimeout(() => {
        setRestoreMessage('');
        router.push(`/sboms/${restoredVersion.id}`);
      }, 2000);
    } catch (err: any) {
      setRestoreMessage(`Restoration failed: ${err.message}`);
    }
  };

  const invalidateLifecycleQueries = () => {
    invalidateLifecycleOverrideSurfaces(queryClient, sbom.id);
  };

  const handleRefreshLifecycle = async () => {
    setIsRefreshingLifecycle(true);
    setLifecycleMessage('');
    try {
      const result = await refreshSbomLifecycle(sbom.id, true);
      invalidateLifecycleQueries();
      setLifecycleMessage(
        `Lifecycle refreshed: ${result.updated_components} components, ${result.cache_hits} cache hits, ${result.provider_lookups} provider lookups.`,
      );
    } catch (err: any) {
      setLifecycleMessage(err.message || 'Lifecycle refresh failed.');
    } finally {
      setIsRefreshingLifecycle(false);
    }
  };

  const handleRefreshComponentLifecycle = async (component: SBOMComponent) => {
    setRefreshingComponentId(component.id);
    setLifecycleMessage('');
    try {
      await refreshComponentLifecycle(component.id, true);
      invalidateLifecycleQueries();
      setLifecycleMessage(`Lifecycle refreshed for ${component.name}.`);
    } catch (err: any) {
      setLifecycleMessage(err.message || 'Component lifecycle refresh failed.');
    } finally {
      setRefreshingComponentId(null);
    }
  };

  const handleUploadVexDocument = async () => {
    setVexMessage('');
    let document: Record<string, unknown>;
    try {
      document = JSON.parse(vexDocumentText) as Record<string, unknown>;
    } catch {
      setVexMessage('VEX document must be valid JSON.');
      return;
    }

    setIsUploadingVex(true);
    try {
      const result = await uploadSbomVexDocument(sbom.id, {
        document,
        source_name: 'Uploaded VEX',
      });
      setVexMessage(
        `Imported ${result.statements_imported} VEX statements; ${result.unmatched_statements ?? 0} unmatched.`,
      );
      setVexDocumentText('');
      invalidateVexSurfaces(queryClient, sbom.id);
    } catch (err: any) {
      setVexMessage(err.message || 'VEX import failed.');
    } finally {
      setIsUploadingVex(false);
    }
  };

  const handleDiscoverVexDocuments = async () => {
    setIsDiscoveringVex(true);
    setVexMessage('');
    try {
      const result = await discoverSbomVexDocuments(sbom.id, true);
      invalidateVexSurfaces(queryClient, sbom.id);
      const errorSuffix = result.errors?.length ? ` ${result.errors.length} provider error(s) recorded.` : '';
      setVexMessage(
        `Discovery imported ${result.statements_imported} statements from ${result.discovered_documents} document(s); ${result.unmatched_statements} unmatched.${errorSuffix}`,
      );
    } catch (err: any) {
      setVexMessage(err.message || 'VEX discovery failed.');
    } finally {
      setIsDiscoveringVex(false);
    }
  };

  const openVexOverrideModal = async (statement?: VexStatement) => {
    if (!canManageEvidence) return;
    const componentId = statement?.component_id ? String(statement.component_id) : String(componentRows[0]?.id ?? '');
    const vulnerabilityId = statement?.vulnerability_id ?? vulnerabilityOptions[0] ?? '';
    setVexOverrideComponentId(componentId);
    setVexOverrideVulnerability(vulnerabilityId);
    setVexOverrideStatus((statement?.status as VexStatus) || 'under_investigation');
    setVexOverrideJustification(statement?.justification || '');
    setVexOverrideImpact(statement?.impact_statement || '');
    setVexOverrideAction(statement?.action_statement || '');
    setVexOverrideFixedVersion(statement?.fixed_version || '');
    setVexOverrideMitigation(statement?.mitigation || '');
    setVexOverrideEvidenceUrl(statement?.source_url || '');
    setVexOverrideReason('');
    setVexOverrideError('');
    setVexOverrideHistory([]);
    setIsVexOverrideOpen(true);

    if (statement?.component_id && statement.vulnerability_id) {
      setIsLoadingVexHistory(true);
      try {
        const history = await getVexOverrideHistory(statement.component_id, statement.vulnerability_id);
        setVexOverrideHistory(history.history);
      } catch {
        setVexOverrideHistory([]);
      } finally {
        setIsLoadingVexHistory(false);
      }
    }
  };

  const validateVexOverride = () => {
    if (!vexOverrideComponentId) return 'Component is required.';
    if (!vexOverrideVulnerability.trim()) return 'Vulnerability or CVE is required.';
    if (!vexOverrideReason.trim()) return 'Override reason is required.';
    if (vexOverrideStatus === 'not_affected' && !vexOverrideJustification.trim() && !vexOverrideImpact.trim()) {
      return 'not_affected requires justification or impact statement.';
    }
    if (vexOverrideStatus === 'fixed' && !vexOverrideFixedVersion.trim() && !vexOverrideEvidenceUrl.trim()) {
      return 'fixed requires fixed version or evidence URL.';
    }
    return '';
  };

  const handleSubmitVexOverride = async () => {
    const validation = validateVexOverride();
    if (validation) {
      setVexOverrideError(validation);
      return;
    }
    setIsSavingVexOverride(true);
    setVexOverrideError('');
    try {
      await overrideVexStatement(Number(vexOverrideComponentId), vexOverrideVulnerability.trim(), {
        status: vexOverrideStatus,
        justification: vexOverrideJustification.trim() || null,
        impact_statement: vexOverrideImpact.trim() || null,
        action_statement: vexOverrideAction.trim() || null,
        fixed_version: vexOverrideFixedVersion.trim() || null,
        mitigation: vexOverrideMitigation.trim() || null,
        evidence_url: vexOverrideEvidenceUrl.trim() || null,
        reason: vexOverrideReason.trim(),
        updated_by: sbom.created_by || null,
      });
      setVexMessage(`Manual VEX override saved for ${vexOverrideVulnerability.trim()}.`);
      setIsVexOverrideOpen(false);
      invalidateVexSurfaces(queryClient, sbom.id);
    } catch (err: any) {
      setVexOverrideError(err.message || 'Manual VEX override failed.');
    } finally {
      setIsSavingVexOverride(false);
    }
  };

  const handleDownload = async (label: string, loader: () => Promise<{ blob: Blob; filename: string }>) => {
    setDownloadMessage(`Preparing ${label}…`);
    try {
      const { blob, filename } = await loader();
      triggerDownload(blob, filename);
      setDownloadMessage(`Downloaded ${filename}.`);
    } catch (err: any) {
      setDownloadMessage(err.message || `${label} download failed.`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Back button */}
      <button
        onClick={() => router.back()}
        className="flex items-center gap-2 text-sm text-hcl-muted hover:text-hcl-navy transition-colors"
      >
        <ArrowLeft className="h-4 w-4" /> Back to SBOMs
      </button>

      {/* 8-stage validation report */}
      {validationReport && (
        <div id="validation-report">
          <ValidationReportSection
            report={{
              ...validationReport,
              workspace_id: validationReport.workspace_id ?? sbom.workspace_id ?? null,
              validation_session_id: validationReport.validation_session_id ?? sbom.validation_session_id ?? null,
              repair_workspace_url: validationReport.repair_workspace_url ?? sbom.repair_workspace_url ?? null,
              validation_status: validationReport.validation_status ?? sbom.validation_status ?? null,
            }}
          />
        </div>
      )}

      {/* SBOM Tab List Navigation */}
      <div className="flex border-b border-hcl-border gap-6">
        {[
          { id: 'overview', label: 'Overview & Risk', icon: Eye },
          { id: 'components', label: 'Components List', icon: Layers },
          { id: 'normalization', label: 'Normalization', icon: Check },
          { id: 'versions', label: 'Version History', icon: GitBranch },
          { id: 'runs', label: 'Analysis Runs', icon: History }
        ].map(tab => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center gap-2 pb-3 text-sm font-semibold transition-all border-b-2 -mb-[2px] ${
                activeTab === tab.id
                  ? 'border-hcl-blue text-hcl-blue'
                  : 'border-transparent text-hcl-muted hover:text-hcl-navy'
              }`}
            >
              <Icon className="h-4 w-4" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* TAB 1: OVERVIEW */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle>SBOM Details</CardTitle>
              <div className="flex gap-2">
                {canUseWorkspace ? (
                  <Button
                    onClick={() => void handleOpenRepairWorkspace()}
                    loading={isOpeningWorkspace}
                    disabled={isOpeningWorkspace}
                    variant="outline"
                    size="sm"
                  >
                    {workspaceButtonLabel}
                  </Button>
                ) : null}
                <Button
                  onClick={() => {
                    setDetailName(sbom.sbom_name || '');
                    setDetailProductName(sbom.product_name || '');
                    setDetailProductVersion(sbom.productver || '');
                    setDetailSbomVersion(sbom.sbom_version || '');
                    setDetailDescription(sbom.description || '');
                    setDetailProjectId(sbom.projectid || null);
                    setDetailChangeReason('');
                    setDetailsError('');
                    setIsEditDetailsModalOpen(true);
                  }}
                  variant="outline"
                  size="sm"
                >
                  <Edit2 className="h-3.5 w-3.5" /> Edit Details
                </Button>
                <a
                  href={`${BASE_URL}/api/sboms/${sbom.id}/export?export_mode=original`}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-hcl-border text-xs font-semibold hover:bg-hcl-light transition-colors text-hcl-navy"
                  download
                >
                  <Download className="h-3.5 w-3.5" />{' '}
                  {info?.format === 'SPDX' || sbom.format === 'spdx'
                    ? 'Export Original SPDX'
                    : 'Export CycloneDX'}
                </a>
                <Button
                  onClick={() =>
                    handleDownload('vulnerability Excel', () => exportSbomVulnerabilityExcel(sbom.id))
                  }
                  variant="outline"
                  size="sm"
                >
                  <Download className="h-3.5 w-3.5" /> Export Vulnerability Excel
                </Button>
                <Button
                  onClick={handleRunAnalysis}
                  loading={isAnalyzing}
                  disabled={isAnalyzing}
                  size="sm"
                >
                  <Play className="h-4 w-4" />
                  {isAnalyzing ? 'Analyzing…' : 'Run Analysis'}
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              <dl className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {[
                  { label: 'Name', value: sbom.sbom_name },
                  { label: 'Product Name', value: sbom.product_name || '—' },
                  { label: 'Product Version', value: sbom.productver || '—' },
                  { label: 'SBOM Version', value: sbom.sbom_version || '1.0.0' },
                  { label: 'Format / Type', value: formatTypeDisplay },
                  {
                    label: 'Project',
                    value: (
                      <div className="flex items-center gap-2">
                        <span>{sbom.project_name || (sbom.projectid ? `Project #${sbom.projectid}` : '—')}</span>
                        <button
                          type="button"
                          onClick={() => {
                            setSelectedProjectId(sbom.projectid || null);
                            setAssignChangeReason('');
                            setAssignError('');
                            setIsAssignModalOpen(true);
                          }}
                          className="text-xs text-hcl-blue hover:underline font-semibold"
                        >
                          {sbom.projectid ? 'Change' : 'Assign'}
                        </button>
                      </div>
                    ),
                  },
                  { label: 'Created By', value: sbom.created_by || '—' },
                  { label: 'Created On', value: formatDate(sbom.created_on) },
                  { label: 'Updated On', value: formatDate(sbom.modified_on) },
                  { label: 'Description', value: sbom.description || '—', fullWidth: true },
                ].map(({ label, value, fullWidth }) => (
                  <div key={label} className={fullWidth ? 'col-span-2 md:col-span-4' : ''}>
                    <dt className="text-xs font-medium text-hcl-muted uppercase tracking-wide">{label}</dt>
                    <dd className="mt-1 text-sm font-medium text-hcl-navy break-words">{value}</dd>
                  </div>
                ))}
              </dl>
            </CardContent>
          </Card>

          <ScheduleCard scope="SBOM" targetId={sbom.id} />

          <SbomConversionCard sbom={sbom} formatLabel={info?.format} />

          <SbomRawViewer
            sbomId={sbom.id}
            stats={documentStats}
            workspaceUnavailableReason={workspaceUnavailableReason}
            workspaceAction={
              canUseWorkspace ? (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => void handleOpenRepairWorkspace()}
                  loading={isOpeningWorkspace}
                  disabled={isOpeningWorkspace}
                >
                  {workspaceDocumentButtonLabel}
                </Button>
              ) : null
            }
          />

          {info && (
            <Card>
              <CardHeader>
                <CardTitle>Format &amp; Ecosystems</CardTitle>
              </CardHeader>
              <CardContent>
                <dl className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div>
                    <dt className="text-xs font-medium text-hcl-muted uppercase tracking-wide">Format</dt>
                    <dd className="mt-1 text-sm font-medium text-hcl-navy">{info.format}</dd>
                  </div>
                  <div>
                    <dt className="text-xs font-medium text-hcl-muted uppercase tracking-wide">Spec Version</dt>
                    <dd className="mt-1 text-sm font-medium text-hcl-navy">{info.spec_version || '—'}</dd>
                  </div>
                  <div>
                    <dt className="text-xs font-medium text-hcl-muted uppercase tracking-wide">Components</dt>
                    <dd className="mt-1 text-sm font-medium text-hcl-navy">
                      {(documentStats?.component_count ?? info.component_count).toLocaleString()}
                      {documentStats && documentStats.parsed_component_count !== documentStats.component_count
                        ? ` (${documentStats.parsed_component_count.toLocaleString()} parsed)`
                        : null}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-xs font-medium text-hcl-muted uppercase tracking-wide">Identifiers</dt>
                    <dd className="mt-1 text-sm font-medium text-hcl-navy">
                      {info.has_purls && 'PURL'}
                      {info.has_purls && info.has_cpes && ' · '}
                      {info.has_cpes && 'CPE'}
                      {!info.has_purls && !info.has_cpes && '—'}
                    </dd>
                  </div>
                </dl>
              </CardContent>
            </Card>
          )}

          {risk && (
            <Card>
              <CardHeader>
                <CardTitle>
                  Risk Summary
                  <span className="ml-2 text-xs font-normal text-hcl-muted">Top 10 vulnerable components</span>
                  <span
                    className={`ml-3 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold border ${
                      risk.risk_band === 'CRITICAL'
                        ? 'bg-red-50 text-red-700 border-red-200'
                        : risk.risk_band === 'HIGH'
                        ? 'bg-orange-50 text-orange-700 border-orange-200'
                        : risk.risk_band === 'MEDIUM'
                        ? 'bg-amber-50 text-amber-700 border-amber-200'
                        : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                    }`}
                  >
                    {risk.risk_band} · score {risk.total_risk_score.toFixed(1)}
                  </span>
                </CardTitle>
              </CardHeader>
              <div className="overflow-hidden">
                <Table striped ariaLabel="Risk by vulnerable component">
                  <TableHead>
                    <tr>
                      <Th>Component</Th>
                      <Th>Critical</Th>
                      <Th>High</Th>
                      <Th>Medium</Th>
                      <Th>Low</Th>
                      <Th>KEV</Th>
                      <Th className="text-right">Score</Th>
                    </tr>
                  </TableHead>
                  <TableBody>
                    {risk.components.length === 0 ? (
                      <EmptyRow cols={7} message="No vulnerable components." />
                    ) : (
                      risk.components.slice(0, 10).map((c) => (
                        <tr key={`${c.name}@${c.version}`} className="hover:bg-hcl-light/40">
                          <Td className="font-medium text-hcl-navy">
                            {c.name}
                            {c.version && <span className="text-hcl-muted"> @ {c.version}</span>}
                          </Td>
                          <Td className="text-red-700">{c.critical}</Td>
                          <Td className="text-orange-700">{c.high}</Td>
                          <Td className="text-amber-700">{c.medium}</Td>
                          <Td className="text-hcl-blue">{c.low}</Td>
                          <Td className={c.kev_count && c.kev_count > 0 ? 'text-red-700 font-semibold' : 'text-hcl-muted'}>
                            {c.kev_count ?? 0}
                          </Td>
                          <Td className="text-right font-mono text-xs text-hcl-navy">
                            {c.component_score.toFixed(1)}
                          </Td>
                        </tr>
                      ))
                    )}
                  </TableBody>
                </Table>
              </div>
            </Card>
          )}

          <Card>
            <CardHeader className="flex flex-row items-center justify-between gap-3">
              <div>
                <CardTitle>VEX Statements</CardTitle>
                {downloadMessage ? <p className="mt-1 text-xs text-hcl-muted">{downloadMessage}</p> : null}
              </div>
              <div className="flex flex-wrap justify-end gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => handleDownload('VEX JSON', () => exportSbomVexReportJson(sbom.id))}
                >
                  <Download className="h-3.5 w-3.5" /> JSON
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => handleDownload('VEX CSV', () => exportSbomVexReportCsv(sbom.id))}
                >
                  <Download className="h-3.5 w-3.5" /> CSV
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => handleDownload('VEX report pack', () => exportSbomVexReportPack(sbom.id))}
                >
                  <Download className="h-3.5 w-3.5" /> Pack
                </Button>
                {canManageEvidence ? (
                  <>
                    <Button size="sm" variant="outline" onClick={handleDiscoverVexDocuments} loading={isDiscoveringVex}>
                      <RefreshCw className="h-3.5 w-3.5" /> Discover
                    </Button>
                    <Button size="sm" onClick={() => openVexOverrideModal()}>
                      <Edit2 className="h-3.5 w-3.5" /> Override
                    </Button>
                  </>
                ) : null}
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {vexIsError ? (
                <div className="rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-800">
                  VEX statements could not be loaded.
                </div>
              ) : null}
              <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
                {([
                  ['Affected', vexCounts.affected ?? 0, 'text-red-700'],
                  ['Not Affected', vexCounts.not_affected ?? 0, 'text-emerald-700'],
                  ['Fixed', vexCounts.fixed ?? 0, 'text-blue-700'],
                  ['Investigating', vexCounts.under_investigation ?? 0, 'text-amber-700'],
                  ['Unknown', vexCounts.unknown ?? 0, 'text-gray-700'],
                ] as const).map(([label, value, color]) => (
                  <div key={label} className="rounded-lg border border-hcl-border p-3">
                    <div className="text-[10px] font-semibold uppercase tracking-wide text-hcl-muted">{label}</div>
                    <div className={`mt-1 font-metric text-xl font-semibold ${color}`}>{vexLoading ? '…' : value}</div>
                  </div>
                ))}
              </div>

              <div className="rounded-lg border border-hcl-border p-3">
                <label className="block text-xs font-semibold uppercase tracking-wide text-hcl-muted">
                  Import VEX JSON
                </label>
                <textarea
                  value={vexDocumentText}
                  onChange={(event) => setVexDocumentText(event.target.value)}
                  className="mt-2 min-h-28 w-full rounded-lg border border-hcl-border p-2 font-mono text-xs text-hcl-navy focus:outline-none focus:ring-2 focus:ring-hcl-blue"
                  placeholder='{"bomFormat":"CycloneDX","vulnerabilities":[...]}'
                />
                <div className="mt-2 flex items-center justify-between gap-3">
                  <p className="text-xs text-hcl-muted">{vexMessage}</p>
                  <Button
                    size="sm"
                    onClick={handleUploadVexDocument}
                    loading={isUploadingVex}
                    disabled={!vexDocumentText.trim() || isUploadingVex}
                  >
                    Import VEX
                  </Button>
                </div>
              </div>

              <div className="overflow-hidden rounded-lg border border-hcl-border">
                <Table striped ariaLabel="VEX statements">
                  <TableHead>
                    <tr>
                      <Th>Vulnerability</Th>
                      <Th>Component</Th>
                      <Th>Status</Th>
                      <Th>Source</Th>
                      <Th>Evidence</Th>
                      <Th className="text-right">Actions</Th>
                    </tr>
                  </TableHead>
                  <TableBody>
                    {vexLoading ? (
                      <SkeletonRow cols={6} />
                    ) : vexStatements.length === 0 ? (
                      <EmptyRow cols={6} message="No VEX statements imported for this SBOM." />
                    ) : (
                      vexStatements.slice(0, 10).map((statement) => (
                        <tr key={statement.id} className="hover:bg-hcl-light/40">
                          <Td className="font-mono text-xs text-hcl-navy">{statement.vulnerability_id}</Td>
                          <Td className="text-sm text-hcl-navy">
                            {statement.component_name ?? 'Unmatched'}
                            {statement.component_version ? <span className="text-hcl-muted"> @ {statement.component_version}</span> : null}
                            {!statement.component_id ? (
                              <div className="text-[10px] font-semibold text-amber-700">Low-confidence mapping</div>
                            ) : null}
                          </Td>
                          <Td>
                            <span className="inline-flex rounded-full border border-hcl-border px-2 py-0.5 text-xs font-semibold text-hcl-navy">
                              {String(statement.status).replace('_', ' ')}
                            </span>
                          </Td>
                          <Td className="text-xs text-hcl-muted">{statement.source_name ?? 'VEX'}</Td>
                          <Td className="max-w-xs truncate text-xs text-hcl-muted">
                            {statement.justification || statement.impact_statement || statement.action_statement || '—'}
                          </Td>
                          <Td className="text-right">
                            <button
                              type="button"
                              onClick={() => setEvidenceModal({ kind: 'vex', statement })}
                              className="mr-3 inline-flex items-center gap-1 text-xs font-medium text-hcl-muted transition-colors hover:text-hcl-navy"
                            >
                              <Eye className="h-3 w-3" /> Evidence
                            </button>
                            {canManageEvidence ? (
                              <button
                                type="button"
                                onClick={() => openVexOverrideModal(statement)}
                                className="inline-flex items-center gap-1 text-xs font-medium text-hcl-blue transition-colors hover:text-hcl-navy"
                              >
                                <Edit2 className="h-3 w-3" /> Override
                              </button>
                            ) : null}
                          </Td>
                        </tr>
                      ))
                    )}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* TAB 2: COMPONENTS */}
      {activeTab === 'components' && (
        <div className="space-y-4">
          {/* Deduplication Summary Banner */}
          {dedupeReport && dedupeReport.duplicates_found > 0 && (
            <div className="p-4 bg-amber-50/70 border border-amber-200/60 rounded-xl flex items-center justify-between gap-4">
              <div className="flex items-center gap-2.5">
                <Layers className="h-5 w-5 text-amber-600" />
                <div>
                  <h4 className="text-sm font-semibold text-amber-900">Deduplication Summary</h4>
                  <p className="text-xs text-amber-700 font-medium mt-0.5">
                    Found {dedupeReport.duplicates_found} duplicate component entries. Merged into {dedupeReport.duplicates_found - dedupeReport.duplicates_merged} unique canonical components.
                  </p>
                </div>
              </div>
              <button
                onClick={() => setIsDedupeModalOpen(true)}
                className="px-3 py-1.5 text-xs font-semibold text-amber-800 bg-amber-100 hover:bg-amber-200 rounded-lg transition-colors"
              >
                View Dedupe Report
              </button>
            </div>
          )}

          <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-3">
            <div>
              <CardTitle>Components</CardTitle>
              <p className="mt-1 text-xs text-hcl-muted">
                {showDuplicates ? (
                  <>
                    {componentList?.total_count ?? 0} total · {componentList?.unique_count ?? 0} unique ·{' '}
                    {componentList?.duplicate_count ?? 0} duplicates
                  </>
                ) : (
                  <>
                    {componentList?.unique_count ?? 0} unique
                    {(componentList?.duplicate_count ?? 0) > 0
                      ? ` · Duplicates hidden: ${componentList?.duplicate_count ?? 0}`
                      : ''}
                  </>
                )}
              </p>
              {lifecycleProvidersDegraded ? (
                <p className="mt-1 text-xs font-semibold text-amber-700">
                  Lifecycle provider degraded — evidence may be incomplete. Refresh again later or check provider status.
                </p>
              ) : null}
              {lifecycleMessage ? (
                <p className="mt-1 text-xs text-hcl-muted">{lifecycleMessage}</p>
              ) : null}
              {downloadMessage ? (
                <p className="mt-1 text-xs text-hcl-muted">{downloadMessage}</p>
              ) : null}
            </div>
            <div className="flex flex-wrap items-center justify-end gap-2">
              {(componentList?.duplicate_count ?? dedupeReport?.duplicates_found ?? 0) > 0 ? (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setShowDuplicates((prev) => !prev)}
                >
                  {showDuplicates ? 'Hide Duplicates' : 'Show Duplicates'}
                </Button>
              ) : null}
              <Button
                size="sm"
                variant="outline"
                onClick={() => handleDownload('lifecycle CSV', () => exportSbomLifecycleReportCsv(sbom.id))}
              >
                <Download className="h-3.5 w-3.5" /> Lifecycle CSV
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => handleDownload('lifecycle report pack', () => exportSbomLifecycleReportPack(sbom.id))}
              >
                <Download className="h-3.5 w-3.5" /> Lifecycle Pack
              </Button>
              <Button size="sm" variant="outline" onClick={handleRefreshLifecycle} loading={isRefreshingLifecycle}>
                <RefreshCw className="h-3.5 w-3.5" /> Refresh EOL / EOS Details
              </Button>
            </div>
          </CardHeader>
          {staleLifecycleCount ? (
            <div className="border-y border-amber-200 bg-amber-50 px-4 py-2 text-xs font-medium text-amber-800">
              {staleLifecycleCount} lifecycle evidence record{staleLifecycleCount === 1 ? ' is' : 's are'} stale. Refresh before relying on this report for release decisions.
            </div>
          ) : null}
          <TableFilterBar
            onClear={componentSearch ? () => setComponentSearch('') : undefined}
            clearDisabled={!componentSearch}
            resultHint={
              componentList
                ? `Showing ${componentRangeStart}-${componentRangeEnd} of ${componentList.total_count}`
                : undefined
            }
          >
            <TableSearchInput
              value={componentSearch}
              onChange={setComponentSearch}
              placeholder="Search components by name, version, PURL, CPE…"
              label="Search SBOM components"
            />
          </TableFilterBar>
          <div className="overflow-hidden">
            <Table striped ariaLabel="SBOM components">
              <TableHead>
                <tr>
                  <SortableTh sortKey="name" activeKey={compSort.key} direction={compSort.direction} onToggle={(k) => toggleCompSort(k as ComponentSortKey)}>Name</SortableTh>
                  <SortableTh sortKey="version" activeKey={compSort.key} direction={compSort.direction} onToggle={(k) => toggleCompSort(k as ComponentSortKey)}>Version</SortableTh>
                  <SortableTh sortKey="component_type" activeKey={compSort.key} direction={compSort.direction} onToggle={(k) => toggleCompSort(k as ComponentSortKey)}>Type</SortableTh>
                  <SortableTh sortKey="license" activeKey={compSort.key} direction={compSort.direction} onToggle={(k) => toggleCompSort(k as ComponentSortKey)}>License</SortableTh>
                  <SortableTh sortKey="lifecycle_status" activeKey={compSort.key} direction={compSort.direction} onToggle={(k) => toggleCompSort(k as ComponentSortKey)}>Lifecycle</SortableTh>
                  <Th>EOL / EOS Status</Th>
                  <Th className="text-right">Actions</Th>
                </tr>
              </TableHead>
              <TableBody>
                {compLoading ? (
                  Array.from({ length: 5 }).map((_, i) => <SkeletonRow key={i} cols={7} />)
                ) : !displayedComponents.length ? (
                  <EmptyRow cols={7} message="No components found for this SBOM" />
                ) : (
                  displayedComponents.map((c) => {
                    const eolEosStatus = eolEosStatusForComponent(c);
                    return (
                      <tr
                        key={c.id}
                        className={c.is_duplicate ? 'bg-amber-50/40 hover:bg-amber-50/70' : 'hover:bg-hcl-light/40'}
                      >
                        <Td className="font-medium text-hcl-navy">
                          <div className="flex flex-col">
                            <div className="flex items-center gap-2">
                              <span>{c.name}</span>
                              {c.is_duplicate && (
                                <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold bg-amber-50 text-amber-800 border border-amber-200">
                                  Duplicate
                                </span>
                              )}
                            </div>
                            {c.is_duplicate && (c.canonical_component_name || c.duplicate_of_component_id) && (
                              <span className="text-[10px] text-hcl-muted">
                                Duplicate of {c.canonical_component_name || 'component'}
                                {c.canonical_component_version ? ` ${c.canonical_component_version}` : ''}
                              </span>
                            )}
                            {(c.normalized_name || c.primary_cpe) && (
                              <span className="text-[10px] text-hcl-muted">
                                {c.normalized_name ? `Normalized ${c.normalized_name}` : ''}
                                {c.normalized_version ? ` ${c.normalized_version}` : ''}
                                {c.primary_cpe ? ` · ${c.primary_cpe}` : ''}
                              </span>
                            )}
                          </div>
                        </Td>
                        <Td className="font-mono text-xs">{c.version || '—'}</Td>
                        <Td className="text-hcl-muted">
                          <div>{c.component_type || '—'}</div>
                          {c.ecosystem ? <div className="text-[10px] uppercase tracking-wide">{c.ecosystem}</div> : null}
                        </Td>
                        <Td className="max-w-[120px] truncate">
                          {c.license ? (
                            <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-emerald-50 text-emerald-800 border border-emerald-100 dark:bg-emerald-950/20 dark:text-emerald-300">
                              {c.license}
                            </span>
                          ) : (
                            <span className="text-hcl-muted text-xs font-medium">None</span>
                          )}
                        </Td>
                        <Td>
                          <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold ${lifecycleBadgeClass(c.lifecycle_status)}`}>
                            {lifecycleDisplayLabel(c.lifecycle_status, c.lifecycle_confidence)}
                          </span>
                          <div className="mt-1 max-w-[220px] space-y-0.5 text-[10px] leading-4 text-hcl-muted">
                            {(c.eol_date || c.eos_date || c.eof_date) && (
                              <div>
                                {c.eol_date ? `EOL ${c.eol_date}` : ''}
                                {c.eos_date ? `${c.eol_date ? ' · ' : ''}EOS ${c.eos_date}` : ''}
                                {c.eof_date ? `${c.eol_date || c.eos_date ? ' · ' : ''}EOF ${c.eof_date}` : ''}
                              </div>
                            )}
                            {(c.lifecycle_source || c.lifecycle_confidence) && (
                              <div className="truncate">
                                {c.lifecycle_source || c.lifecycle_provider || 'Provider'} {c.lifecycle_confidence ? `· ${c.lifecycle_confidence}` : ''}
                              </div>
                            )}
                            {c.recommended_version || c.lifecycle_recommendation ? (
                              <div className="truncate text-hcl-navy">
                                {c.recommended_version ? `Upgrade ${c.recommended_version}` : c.lifecycle_recommendation}
                              </div>
                            ) : null}
                            {c.lifecycle_is_stale ? <div className="font-semibold text-amber-700">Stale data</div> : null}
                            {c.lifecycle_manual_override ? <div className="font-semibold text-hcl-blue">Manual override</div> : null}
                          </div>
                        </Td>
                        <Td>
                          <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold ${eolEosStatusBadgeClass(eolEosStatus.status)}`}>
                            {eolEosStatus.label}
                          </span>
                          {eolEosStatus.date ? (
                            <div className="mt-1 text-[10px] leading-4 text-hcl-muted">
                              EOL/EOS {eolEosStatus.date}
                            </div>
                          ) : null}
                        </Td>
                        <Td className="text-right">
                          <button
                            onClick={() => setEvidenceModal({ kind: 'lifecycle', component: c })}
                            className="mr-3 inline-flex items-center gap-1 text-xs font-medium text-hcl-muted transition-colors hover:text-hcl-navy"
                          >
                            <Eye className="h-3 w-3" /> Evidence
                          </button>
                          <button
                            onClick={() => handleRefreshComponentLifecycle(c)}
                            disabled={refreshingComponentId === c.id}
                            className="mr-3 inline-flex items-center gap-1 text-xs font-medium text-hcl-muted transition-colors hover:text-hcl-navy disabled:opacity-60"
                          >
                            <RefreshCw className={`h-3 w-3 ${refreshingComponentId === c.id ? 'animate-spin' : ''}`} /> Refresh
                          </button>
                          <button
                            onClick={() => openEditModal(c)}
                            className="inline-flex items-center gap-1 text-xs text-hcl-blue hover:text-hcl-navy transition-colors font-medium"
                          >
                            <Edit2 className="h-3 w-3" /> Edit
                          </button>
                        </Td>
                    </tr>
                    );
                  })
                )}
              </TableBody>
            </Table>
            {!compLoading && (componentList?.total_count ?? 0) > 0 ? (
              <Pagination
                page={componentPage}
                pageSize={componentPageSize}
                total={componentList?.total_count ?? 0}
                totalPages={componentTotalPages}
                rangeStart={componentRangeStart}
                rangeEnd={componentRangeEnd}
                hasPrev={componentPage > 1}
                hasNext={componentPage < componentTotalPages}
                onPageChange={setComponentPage}
                onPageSizeChange={(size) => {
                  setComponentPageSize(size);
                  setComponentPage(1);
                }}
                itemNoun="component"
              />
            ) : null}
          </div>
        </Card>
      </div>
      )}

      {activeTab === 'normalization' && (
        <div className="space-y-6">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle>Normalization</CardTitle>
                <p className="mt-1 text-xs text-hcl-muted">Stage 9 component identity and duplicate evidence.</p>
              </div>
              {(dedupeReport?.duplicates_found ?? 0) > 0 ? (
                <Button size="sm" variant="outline" onClick={() => setIsDedupeModalOpen(true)}>
                  <Layers className="h-3.5 w-3.5" /> Duplicate Groups
                </Button>
              ) : null}
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                {[
                  ['Total', dedupeReport?.summary?.total_components ?? componentList?.total_count ?? 0],
                  ['Canonical', dedupeReport?.summary?.canonical_components ?? componentList?.unique_count ?? 0],
                  ['Duplicates', dedupeReport?.summary?.duplicate_components ?? componentList?.duplicate_count ?? 0],
                  ['Groups', dedupeReport?.summary?.duplicate_groups ?? 0],
                  ['PURLs', dedupeReport?.summary?.normalized_purls ?? 0],
                ].map(([label, value]) => (
                  <div key={String(label)} className="border border-hcl-border rounded-lg p-3">
                    <div className="text-[10px] uppercase tracking-wide text-hcl-muted">{label}</div>
                    <div className="mt-1 text-xl font-bold text-hcl-navy">{String(value)}</div>
                  </div>
                ))}
              </div>
              {dedupeReport?.duplicate_groups?.length ? (
                <div className="border border-hcl-border rounded-lg overflow-hidden">
                  <Table ariaLabel="Duplicate groups">
                    <TableHead>
                      <tr>
                        <Th>Canonical</Th>
                        <Th>Duplicates</Th>
                        <Th>Confidence</Th>
                        <Th>Reason</Th>
                      </tr>
                    </TableHead>
                    <TableBody>
                      {dedupeReport.duplicate_groups.slice(0, 20).map((group: any) => (
                        <tr key={group.group_id || group.normalized_component_key}>
                          <Td className="font-mono text-xs">{group.canonical_ref || '—'}</Td>
                          <Td className="text-xs">{group.duplicate_refs?.length ?? 0}</Td>
                          <Td className="text-xs">{group.confidence || '—'}</Td>
                          <Td className="text-xs">{group.reason || '—'}</Td>
                        </tr>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              ) : (
                <p className="text-xs text-hcl-muted">No duplicate groups recorded for this SBOM.</p>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* TAB 3: VERSION CONTROL */}
      {activeTab === 'versions' && (
        <div className="space-y-6">
          {restoreMessage && (
            <div className={`p-4 rounded-lg border text-sm font-semibold ${
              restoreMessage.includes('failed') ? 'bg-red-50 border-red-200 text-red-800' : 'bg-emerald-50 border-emerald-200 text-emerald-800'
            }`}>
              {restoreMessage}
            </div>
          )}

          {/* Versions Table */}
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle>Linage &amp; Versions History</CardTitle>
              <div className="flex gap-2">
                <Button
                  onClick={handleCompare}
                  disabled={selectedVersions.length !== 2 || isComparing}
                  size="sm"
                  variant="outline"
                >
                  <RefreshCw className={`h-4 w-4 ${isComparing ? 'animate-spin' : ''}`} />
                  Compare Selected ({selectedVersions.length}/2)
                </Button>
              </div>
            </CardHeader>
            <div className="overflow-hidden">
              <Table striped ariaLabel="SBOM versions">
                <TableHead>
                  <tr>
                    <Th className="w-12"><span className="sr-only">Select</span></Th>
                    <Th>Version</Th>
                    <Th>Change Summary</Th>
                    <Th>Created By</Th>
                    <Th>Date Created</Th>
                    <Th className="text-right">Actions</Th>
                  </tr>
                </TableHead>
                <TableBody>
                  {!versions?.length ? (
                    <EmptyRow cols={6} message="No versions found" />
                  ) : (
                    versions.map((v) => {
                      const isCurrent = v.id === sbom.id;
                      return (
                        <tr key={v.id} className={`hover:bg-hcl-light/40 ${isCurrent ? 'bg-hcl-light/25 font-medium' : ''}`}>
                          <Td>
                            <input
                              type="checkbox"
                              checked={selectedVersions.includes(v.id)}
                              onChange={() => handleSelectVersion(v.id)}
                              className="rounded border-gray-300 text-hcl-blue focus:ring-hcl-blue h-4 w-4"
                            />
                          </Td>
                          <Td className="font-mono text-xs">
                            {v.sbom_version}
                            {isCurrent && (
                              <span className="ml-2 inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold bg-hcl-blue/10 text-hcl-blue border border-hcl-blue/20">
                                Current (HEAD)
                              </span>
                            )}
                          </Td>
                          <Td className="max-w-[250px] truncate text-xs text-hcl-navy">{v.change_summary || 'Initial creation'}</Td>
                          <Td className="text-xs text-hcl-muted">{v.created_by || '—'}</Td>
                          <Td className="text-xs text-hcl-muted whitespace-nowrap">{formatDate(v.created_on)}</Td>
                          <Td className="text-right flex items-center justify-end gap-3">
                            <a
                              href={`${BASE_URL}/api/sboms/${v.id}/export`}
                              className="inline-flex items-center gap-1 text-xs text-hcl-muted hover:text-hcl-navy"
                              download
                            >
                              <Download className="h-3.5 w-3.5" />
                              Export CycloneDX
                            </a>
                            {!isCurrent && (
                              <button
                                onClick={() => handleRestore(v.id)}
                                className="inline-flex items-center gap-1 text-xs text-hcl-blue hover:underline font-semibold"
                              >
                                Restore
                              </button>
                            )}
                          </Td>
                        </tr>
                      );
                    })
                  )}
                </TableBody>
              </Table>
            </div>
          </Card>

          {/* Comparison Output */}
          {compareData && (
            <Card>
              <CardHeader className="flex flex-row items-center justify-between">
                <div>
                  <CardTitle>Version Difference Comparison</CardTitle>
                  <p className="mt-0.5 text-xs text-hcl-muted">
                    Comparing selected versions: Added, Removed, and Modified components
                  </p>
                </div>
                <button onClick={() => setCompareData(null)} className="text-hcl-muted hover:text-hcl-navy p-1">
                  <X className="h-4 w-4" />
                </button>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-3 gap-4">
                  <div className="p-3 bg-emerald-50/70 border border-emerald-100 rounded-xl text-center dark:bg-emerald-950/15">
                    <div className="text-[10px] font-semibold text-emerald-800 uppercase dark:text-emerald-300">Added Components</div>
                    <div className="mt-1 text-2xl font-bold text-emerald-700 dark:text-emerald-400">{compareData.total_added}</div>
                  </div>
                  <div className="p-3 bg-red-50/70 border border-red-100 rounded-xl text-center dark:bg-red-950/15">
                    <div className="text-[10px] font-semibold text-red-800 uppercase dark:text-red-300">Removed Components</div>
                    <div className="mt-1 text-2xl font-bold text-red-700 dark:text-red-400">{compareData.total_removed}</div>
                  </div>
                  <div className="p-3 bg-amber-50/70 border border-amber-100 rounded-xl text-center dark:bg-amber-950/15">
                    <div className="text-[10px] font-semibold text-amber-800 uppercase dark:text-amber-300">Modified Components</div>
                    <div className="mt-1 text-2xl font-bold text-amber-700 dark:text-amber-400">{compareData.total_changed}</div>
                  </div>
                </div>

                {/* Added List */}
                {compareData.added.length > 0 && (
                  <div>
                    <h4 className="text-xs font-bold text-emerald-800 uppercase border-b pb-1">Added Details</h4>
                    <ul className="mt-2 space-y-1 text-xs">
                      {compareData.added.map((c: any, i: number) => (
                        <li key={i} className="flex justify-between p-1 hover:bg-hcl-light/40">
                          <span className="font-semibold text-hcl-navy">{c.name}</span>
                          <span className="font-mono text-hcl-muted">v{c.version || '—'}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Removed List */}
                {compareData.removed.length > 0 && (
                  <div className="pt-2">
                    <h4 className="text-xs font-bold text-red-800 uppercase border-b pb-1">Removed Details</h4>
                    <ul className="mt-2 space-y-1 text-xs">
                      {compareData.removed.map((c: any, i: number) => (
                        <li key={i} className="flex justify-between p-1 hover:bg-hcl-light/40">
                          <span className="font-semibold text-red-700">{c.name}</span>
                          <span className="font-mono text-hcl-muted">v{c.version || '—'}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Changed List */}
                {compareData.changed.length > 0 && (
                  <div className="pt-2">
                    <h4 className="text-xs font-bold text-amber-800 uppercase border-b pb-1">Modified Details</h4>
                    <ul className="mt-2 space-y-3 text-xs">
                      {compareData.changed.map((c: any, i: number) => (
                        <li key={i} className="p-2 border border-amber-100 bg-amber-50/20 rounded-lg dark:bg-amber-950/10 dark:border-amber-900/50">
                          <div className="font-semibold text-hcl-navy text-sm">{c.name} <span className="font-mono text-xs text-hcl-muted">({c.version})</span></div>
                          <div className="mt-1 space-y-1">
                            {Object.entries(c.changes).map(([field, delta]: any) => (
                              <div key={field} className="flex items-center gap-2 text-[11px]">
                                <span className="font-medium capitalize text-hcl-muted w-24">{field.replace('_', ' ')}:</span>
                                <span className="bg-red-50 text-red-800 px-1 rounded line-through dark:bg-red-950/30 dark:text-red-400">{delta.old || '—'}</span>
                                <ArrowRight className="h-3 w-3 text-hcl-muted" />
                                <span className="bg-emerald-50 text-emerald-800 px-1 rounded font-semibold dark:bg-emerald-950/30 dark:text-emerald-400">{delta.new || '—'}</span>
                              </div>
                            ))}
                          </div>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* TAB 4: RUNS */}
      {activeTab === 'runs' && (
        <Card>
          <CardHeader>
            <CardTitle>Analysis Runs</CardTitle>
          </CardHeader>
          <div className="overflow-hidden">
            <Table striped ariaLabel="Analysis runs for this SBOM">
              <TableHead>
                <tr>
                  <SortableTh sortKey="id" activeKey={runSort.key} direction={runSort.direction} onToggle={(k) => toggleRunSort(k as RunSortKey)}>Run ID</SortableTh>
                  <SortableTh sortKey="run_status" activeKey={runSort.key} direction={runSort.direction} onToggle={(k) => toggleRunSort(k as RunSortKey)}>Status</SortableTh>
                  <SortableTh sortKey="total_findings" activeKey={runSort.key} direction={runSort.direction} onToggle={(k) => toggleRunSort(k as RunSortKey)}>Findings</SortableTh>
                  <SortableTh sortKey="duration_ms" activeKey={runSort.key} direction={runSort.direction} onToggle={(k) => toggleRunSort(k as RunSortKey)}>Duration</SortableTh>
                  <SortableTh sortKey="started_on" activeKey={runSort.key} direction={runSort.direction} onToggle={(k) => toggleRunSort(k as RunSortKey)}>Started On</SortableTh>
                  <Th className="text-right">Actions</Th>
                </tr>
              </TableHead>
              <TableBody>
                {runsLoading ? (
                  Array.from({ length: 3 }).map((_, i) => <SkeletonRow key={i} cols={6} />)
                ) : !runs?.length ? (
                  <EmptyRow cols={6} message="No analysis runs yet. Click 'Run Analysis' to get started." />
                ) : (
                  runPagination.pageItems.map((run) => (
                    <tr key={run.id} className="hover:bg-hcl-light/40">
                      <Td className="font-mono text-xs text-hcl-muted">#{run.id}</Td>
                      <Td><StatusBadge status={run.run_status} /></Td>
                      <Td className="text-foreground/90">{run.total_findings ?? '—'}</Td>
                      <Td className="text-hcl-muted">{formatDuration(run.duration_ms)}</Td>
                      <Td className="text-hcl-muted whitespace-nowrap">{formatDate(run.started_on)}</Td>
                      <Td className="text-right">
                        <Link
                          href={`/analysis/${run.id}`}
                          className="inline-flex items-center gap-1 text-xs text-hcl-blue hover:underline font-medium"
                        >
                          View <ExternalLink className="h-3 w-3" />
                        </Link>
                      </Td>
                    </tr>
                  ))
                )}
              </TableBody>
            </Table>
            {!runsLoading && runRows.length > 0 ? (
              <Pagination
                page={runPagination.page}
                pageSize={runPagination.pageSize}
                total={runPagination.total}
                totalPages={runPagination.totalPages}
                rangeStart={runPagination.rangeStart}
                rangeEnd={runPagination.rangeEnd}
                hasPrev={runPagination.hasPrev}
                hasNext={runPagination.hasNext}
                onPageChange={runPagination.setPage}
                onPageSizeChange={runPagination.setPageSize}
                itemNoun="run"
                pageSizeOptions={[5, 10, 25, 50]}
              />
            ) : null}
          </div>
        </Card>
      )}

      <Dialog
        open={Boolean(evidenceModal)}
        onClose={() => setEvidenceModal(null)}
        title={evidenceModal?.kind === 'vex' ? 'VEX Evidence' : 'Lifecycle Evidence'}
        maxWidth="xl"
        footer={
          evidenceModal?.kind === 'lifecycle' ? (
            <div className="flex items-center justify-end gap-2 px-6 py-4">
              {canManageEvidence ? (
                <>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => evidenceModal && handleRefreshComponentLifecycle(evidenceModal.component)}
                    loading={evidenceModal ? refreshingComponentId === evidenceModal.component.id : false}
                  >
                    <RefreshCw className="h-3.5 w-3.5" /> Refresh
                  </Button>
                  <Button
                    size="sm"
                    onClick={() => {
                      if (evidenceModal?.kind === 'lifecycle') {
                        openEditModal(evidenceModal.component);
                        setEvidenceModal(null);
                      }
                    }}
                  >
                    <Edit2 className="h-3.5 w-3.5" /> Override
                  </Button>
                </>
              ) : null}
            </div>
          ) : evidenceModal?.kind === 'vex' ? (
            <div className="flex items-center justify-end gap-2 px-6 py-4">
              {canManageEvidence ? (
                <Button
                  size="sm"
                  onClick={() => {
                    if (evidenceModal?.kind === 'vex') {
                      openVexOverrideModal(evidenceModal.statement);
                      setEvidenceModal(null);
                    }
                  }}
                >
                  <Edit2 className="h-3.5 w-3.5" /> Override
                </Button>
              ) : null}
            </div>
          ) : null
        }
      >
        <DialogBody className="space-y-4">
          {evidenceModal?.kind === 'lifecycle' ? (
            <>
              <div className="grid gap-3 md:grid-cols-2">
                {[
                  ['Component', `${evidenceModal.component.name}${evidenceModal.component.version ? ` @ ${evidenceModal.component.version}` : ''}`],
                  ['Status', lifecycleDisplayLabel(evidenceModal.component.lifecycle_status, evidenceModal.component.lifecycle_confidence)],
                  ['Source', evidenceModal.component.lifecycle_source || evidenceModal.component.lifecycle_provider || 'Unknown'],
                  ['Confidence', evidenceModal.component.lifecycle_confidence || 'Unknown'],
                  ['Checked', formatDate(evidenceModal.component.lifecycle_checked_at)],
                  ['Stale', evidenceModal.component.lifecycle_is_stale ? 'Yes' : 'No'],
                  ['Provider', evidenceModal.component.lifecycle_source || evidenceModal.component.lifecycle_provider || 'Unknown'],
                  ['Recommendation', evidenceModal.component.lifecycle_recommendation || evidenceModal.component.recommended_version || 'None recorded'],
                ].map(([label, value]) => (
                  <div key={label} className="rounded-lg border border-hcl-border p-3">
                    <div className="text-[10px] font-semibold uppercase tracking-wide text-hcl-muted">{label}</div>
                    <div className="mt-1 break-words text-sm font-medium text-hcl-navy">{value}</div>
                  </div>
                ))}
              </div>
              {evidenceModal.component.lifecycle_source_url ? (
                <a
                  href={evidenceModal.component.lifecycle_source_url}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 text-xs font-semibold text-hcl-blue hover:underline"
                >
                  Open source <ExternalLink className="h-3 w-3" />
                </a>
              ) : null}
              <div>
                <div className="text-xs font-semibold uppercase tracking-wide text-hcl-muted">Raw Evidence Summary</div>
                <pre className="mt-2 max-h-72 overflow-auto rounded-lg border border-hcl-border bg-hcl-light/40 p-3 text-xs text-hcl-navy">
                  {jsonSummary(evidenceModal.component.lifecycle_evidence_json)}
                </pre>
              </div>
            </>
          ) : evidenceModal?.kind === 'vex' ? (
            <>
              <div className="grid gap-3 md:grid-cols-2">
                {[
                  ['Vulnerability', evidenceModal.statement.vulnerability_id],
                  ['Component', evidenceModal.statement.component_name ? `${evidenceModal.statement.component_name}${evidenceModal.statement.component_version ? ` @ ${evidenceModal.statement.component_version}` : ''}` : 'Unmatched'],
                  ['Status', labelize(evidenceModal.statement.status)],
                  ['Source', evidenceModal.statement.source_name || 'VEX'],
                  ['Confidence', evidenceModal.statement.confidence || 'Unknown'],
                  ['Checked', formatDate(evidenceModal.statement.created_at)],
                  ['Stale', evidenceModal.statement.evidence_json?.stale ? 'Yes' : 'No stale signal'],
                  ['Reason', String(evidenceModal.statement.evidence_json?.reason || evidenceModal.statement.evidence_json?.mapping || 'Not recorded')],
                  ['Recommendation', evidenceModal.statement.action_statement || evidenceModal.statement.mitigation || evidenceModal.statement.fixed_version || 'None recorded'],
                  ['Provider', evidenceModal.statement.source_name || 'VEX'],
                ].map(([label, value]) => (
                  <div key={label} className="rounded-lg border border-hcl-border p-3">
                    <div className="text-[10px] font-semibold uppercase tracking-wide text-hcl-muted">{label}</div>
                    <div className="mt-1 break-words text-sm font-medium text-hcl-navy">{value}</div>
                  </div>
                ))}
              </div>
              {evidenceModal.statement.source_url ? (
                <a
                  href={evidenceModal.statement.source_url}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 text-xs font-semibold text-hcl-blue hover:underline"
                >
                  Open source <ExternalLink className="h-3 w-3" />
                </a>
              ) : null}
              <div>
                <div className="text-xs font-semibold uppercase tracking-wide text-hcl-muted">Raw Evidence Summary</div>
                <pre className="mt-2 max-h-72 overflow-auto rounded-lg border border-hcl-border bg-hcl-light/40 p-3 text-xs text-hcl-navy">
                  {jsonSummary(evidenceModal.statement.evidence_json)}
                </pre>
              </div>
            </>
          ) : null}
        </DialogBody>
      </Dialog>

      <Dialog
        open={isVexOverrideOpen}
        onClose={() => setIsVexOverrideOpen(false)}
        title="Manual VEX Override"
        maxWidth="xl"
        footer={
          <div className="flex items-center justify-end gap-2 px-6 py-4">
            <Button size="sm" variant="ghost" onClick={() => setIsVexOverrideOpen(false)}>
              Cancel
            </Button>
            <Button size="sm" onClick={handleSubmitVexOverride} loading={isSavingVexOverride}>
              Save Override
            </Button>
          </div>
        }
      >
        <DialogBody className="space-y-4">
          {vexOverrideError ? (
            <div className="rounded-lg border border-red-200 bg-red-50 p-3 text-xs font-medium text-red-800">
              {vexOverrideError}
            </div>
          ) : null}
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wide text-hcl-muted">Component</label>
              <select
                aria-label="Component"
                value={vexOverrideComponentId}
                onChange={(event) => setVexOverrideComponentId(event.target.value)}
                className="mt-1 w-full rounded-lg border border-hcl-border p-2 text-sm text-hcl-navy focus:outline-none focus:ring-2 focus:ring-hcl-blue"
              >
                <option value="">Select component</option>
                {componentRows.map((component) => (
                  <option key={component.id} value={component.id}>
                    {component.name}{component.version ? ` @ ${component.version}` : ''}
                  </option>
                ))}
              </select>
              {selectedOverrideComponent ? (
                <p className="mt-1 text-[11px] text-hcl-muted">
                  {selectedOverrideComponent.purl || selectedOverrideComponent.cpe || selectedOverrideComponent.supplier || 'No package identifier recorded.'}
                </p>
              ) : null}
            </div>
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wide text-hcl-muted">Vulnerability / CVE</label>
              <input
                aria-label="Vulnerability or CVE"
                list="vex-vulnerability-options"
                value={vexOverrideVulnerability}
                onChange={(event) => setVexOverrideVulnerability(event.target.value)}
                className="mt-1 w-full rounded-lg border border-hcl-border p-2 font-mono text-sm text-hcl-navy focus:outline-none focus:ring-2 focus:ring-hcl-blue"
                placeholder="CVE-2026-0001"
              />
              <datalist id="vex-vulnerability-options">
                {vulnerabilityOptions.map((id) => (
                  <option key={id} value={id} />
                ))}
              </datalist>
            </div>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wide text-hcl-muted">VEX Status</label>
              <select
                aria-label="VEX Status"
                value={vexOverrideStatus}
                onChange={(event) => setVexOverrideStatus(event.target.value as VexStatus)}
                className="mt-1 w-full rounded-lg border border-hcl-border p-2 text-sm text-hcl-navy focus:outline-none focus:ring-2 focus:ring-hcl-blue"
              >
                {VEX_STATUSES.map((status) => (
                  <option key={status} value={status}>
                    {labelize(status)}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wide text-hcl-muted">Evidence URL</label>
              <input
                aria-label="Evidence URL"
                type="url"
                value={vexOverrideEvidenceUrl}
                onChange={(event) => setVexOverrideEvidenceUrl(event.target.value)}
                className="mt-1 w-full rounded-lg border border-hcl-border p-2 text-sm text-hcl-navy focus:outline-none focus:ring-2 focus:ring-hcl-blue"
                placeholder="https://vendor.example/security/advisory"
              />
            </div>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wide text-hcl-muted">Justification</label>
              <input
                aria-label="Justification"
                value={vexOverrideJustification}
                onChange={(event) => setVexOverrideJustification(event.target.value)}
                className="mt-1 w-full rounded-lg border border-hcl-border p-2 text-sm text-hcl-navy focus:outline-none focus:ring-2 focus:ring-hcl-blue"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wide text-hcl-muted">Fixed Version</label>
              <input
                aria-label="Fixed Version"
                value={vexOverrideFixedVersion}
                onChange={(event) => setVexOverrideFixedVersion(event.target.value)}
                className="mt-1 w-full rounded-lg border border-hcl-border p-2 text-sm text-hcl-navy focus:outline-none focus:ring-2 focus:ring-hcl-blue"
              />
            </div>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wide text-hcl-muted">Impact Statement</label>
              <textarea
                aria-label="Impact Statement"
                value={vexOverrideImpact}
                onChange={(event) => setVexOverrideImpact(event.target.value)}
                className="mt-1 min-h-24 w-full rounded-lg border border-hcl-border p-2 text-sm text-hcl-navy focus:outline-none focus:ring-2 focus:ring-hcl-blue"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wide text-hcl-muted">Action Statement</label>
              <textarea
                aria-label="Action Statement"
                value={vexOverrideAction}
                onChange={(event) => setVexOverrideAction(event.target.value)}
                className="mt-1 min-h-24 w-full rounded-lg border border-hcl-border p-2 text-sm text-hcl-navy focus:outline-none focus:ring-2 focus:ring-hcl-blue"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase tracking-wide text-hcl-muted">Mitigation</label>
            <textarea
              aria-label="Mitigation"
              value={vexOverrideMitigation}
              onChange={(event) => setVexOverrideMitigation(event.target.value)}
              className="mt-1 min-h-20 w-full rounded-lg border border-hcl-border p-2 text-sm text-hcl-navy focus:outline-none focus:ring-2 focus:ring-hcl-blue"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase tracking-wide text-hcl-muted">Reason for Override</label>
            <textarea
              aria-label="Reason for Override"
              value={vexOverrideReason}
              onChange={(event) => setVexOverrideReason(event.target.value)}
              className="mt-1 min-h-20 w-full rounded-lg border border-hcl-border p-2 text-sm text-hcl-navy focus:outline-none focus:ring-2 focus:ring-hcl-blue"
            />
          </div>

          <div className="rounded-lg border border-hcl-border p-3">
            <div className="text-xs font-semibold uppercase tracking-wide text-hcl-muted">Audit History</div>
            {isLoadingVexHistory ? (
              <p className="mt-2 text-xs text-hcl-muted">Loading audit history…</p>
            ) : vexOverrideHistory.length ? (
              <ul className="mt-2 space-y-2">
                {vexOverrideHistory.map((entry) => (
                  <li key={entry.id} className="rounded-lg bg-hcl-light/50 p-2 text-xs text-hcl-navy">
                    <div className="font-semibold">{entry.reason}</div>
                    <div className="mt-0.5 text-hcl-muted">
                      {entry.changed_by || 'Unknown user'} · {formatDate(entry.changed_at)}
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="mt-2 text-xs text-hcl-muted">No manual override history for this vulnerability/component pair.</p>
            )}
          </div>
        </DialogBody>
      </Dialog>

      {/* EDIT COMPONENT MODAL OVERLAY */}
      {editingComp && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <Card className="w-full max-w-lg bg-white shadow-2xl overflow-y-auto max-h-[90vh]">
            <CardHeader className="flex flex-row items-center justify-between border-b pb-3">
              <CardTitle>Edit Component Override</CardTitle>
              <button onClick={() => setEditingComp(null)} className="text-hcl-muted hover:text-hcl-navy">
                <X className="h-5 w-5" />
              </button>
            </CardHeader>
            <CardContent className="p-6 space-y-4">
              {editError && (
                <div className="p-3 bg-red-50 text-red-800 text-xs rounded border border-red-200">
                  {editError}
                </div>
              )}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-hcl-muted uppercase">Name</label>
                  <input
                    type="text"
                    value={editName}
                    onChange={(e) => setEditName(e.target.value)}
                    className="mt-1 w-full rounded-lg border border-hcl-border p-2 text-sm text-hcl-navy focus:outline-none focus:ring-2 focus:ring-hcl-blue"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-hcl-muted uppercase">Version</label>
                  <input
                    type="text"
                    value={editVersion}
                    onChange={(e) => setEditVersion(e.target.value)}
                    className="mt-1 w-full rounded-lg border border-hcl-border p-2 text-sm text-hcl-navy focus:outline-none focus:ring-2 focus:ring-hcl-blue"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-hcl-muted uppercase">Supplier</label>
                  <input
                    type="text"
                    value={editSupplier}
                    onChange={(e) => setEditSupplier(e.target.value)}
                    className="mt-1 w-full rounded-lg border border-hcl-border p-2 text-sm text-hcl-navy focus:outline-none focus:ring-2 focus:ring-hcl-blue"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-hcl-muted uppercase">License</label>
                  <input
                    type="text"
                    value={editLicense}
                    onChange={(e) => setEditLicense(e.target.value)}
                    className="mt-1 w-full rounded-lg border border-hcl-border p-2 text-sm text-hcl-navy focus:outline-none focus:ring-2 focus:ring-hcl-blue"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-hcl-muted uppercase">Hashes (SHA-256)</label>
                <input
                  type="text"
                  value={editHashes}
                  onChange={(e) => setEditHashes(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-hcl-border p-2 text-sm text-hcl-navy font-mono text-xs focus:outline-none focus:ring-2 focus:ring-hcl-blue"
                  placeholder="SHA-256 hex string"
                />
              </div>

              <div className="border-t pt-3 space-y-3">
                <h4 className="text-xs font-bold text-hcl-navy uppercase">Lifecycle Management Parameters</h4>
                
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label htmlFor="edit-lifecycle-status" className="block text-xs font-semibold text-hcl-muted uppercase">Lifecycle Status</label>
                    <select
                      id="edit-lifecycle-status"
                      value={editLifecycleStatus}
                      onChange={(e) => setEditLifecycleStatus(e.target.value)}
                      className="mt-1 w-full rounded-lg border border-hcl-border p-2 text-sm text-hcl-navy focus:outline-none focus:ring-2 focus:ring-hcl-blue"
                    >
                      <option value="Supported">Supported</option>
                      <option value="EOL">End of Life (EOL)</option>
                      <option value="EOS">End of Support (EOS)</option>
                      <option value="EOF">End of Fix (EOF)</option>
                      <option value="Deprecated">Deprecated</option>
                      <option value="Unsupported">Unsupported</option>
                      <option value="EOL Soon">EOL Soon</option>
                      <option value="Unknown">Unknown</option>
                    </select>
                  </div>
                  <div>
                    <label htmlFor="edit-maintenance-status" className="block text-xs font-semibold text-hcl-muted uppercase">Maintenance Status</label>
                    <select
                      id="edit-maintenance-status"
                      value={editMaintStatus}
                      onChange={(e) => setEditMaintStatus(e.target.value)}
                      className="mt-1 w-full rounded-lg border border-hcl-border p-2 text-sm text-hcl-navy focus:outline-none focus:ring-2 focus:ring-hcl-blue"
                    >
                      <option value="Supported">Supported</option>
                      <option value="Active support">Active support</option>
                      <option value="Maintenance only">Maintenance only</option>
                      <option value="Unmaintained">Unmaintained</option>
                      <option value="Unknown">Unknown</option>
                    </select>
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-4">
                  <div>
                    <label htmlFor="edit-eos-date" className="block text-xs font-semibold text-hcl-muted uppercase">EOS Date</label>
                    <input
                      id="edit-eos-date"
                      type="text"
                      placeholder="YYYY-MM-DD"
                      value={editEosDate}
                      onChange={(e) => setEditEosDate(e.target.value)}
                      className="mt-1 w-full rounded-lg border border-hcl-border p-2 text-sm text-hcl-navy focus:outline-none focus:ring-2 focus:ring-hcl-blue"
                    />
                  </div>
                  <div>
                    <label htmlFor="edit-eol-date" className="block text-xs font-semibold text-hcl-muted uppercase">EOL Date</label>
                    <input
                      id="edit-eol-date"
                      type="text"
                      placeholder="YYYY-MM-DD"
                      value={editEolDate}
                      onChange={(e) => setEditEolDate(e.target.value)}
                      className="mt-1 w-full rounded-lg border border-hcl-border p-2 text-sm text-hcl-navy focus:outline-none focus:ring-2 focus:ring-hcl-blue"
                    />
                  </div>
                  <div>
                    <label htmlFor="edit-eof-date" className="block text-xs font-semibold text-hcl-muted uppercase">EOF Date</label>
                    <input
                      id="edit-eof-date"
                      type="text"
                      placeholder="YYYY-MM-DD"
                      value={editEofDate}
                      onChange={(e) => setEditEofDate(e.target.value)}
                      className="mt-1 w-full rounded-lg border border-hcl-border p-2 text-sm text-hcl-navy focus:outline-none focus:ring-2 focus:ring-hcl-blue"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label htmlFor="edit-recommended-version" className="block text-xs font-semibold text-hcl-muted uppercase">Recommended Version</label>
                    <input
                      id="edit-recommended-version"
                      type="text"
                      value={editRecommendedVersion}
                      onChange={(e) => setEditRecommendedVersion(e.target.value)}
                      className="mt-1 w-full rounded-lg border border-hcl-border p-2 text-sm text-hcl-navy focus:outline-none focus:ring-2 focus:ring-hcl-blue"
                    />
                  </div>
                  <div>
                    <label htmlFor="edit-evidence-url" className="block text-xs font-semibold text-hcl-muted uppercase">Evidence URL</label>
                    <input
                      id="edit-evidence-url"
                      type="url"
                      value={editEvidenceUrl}
                      onChange={(e) => setEditEvidenceUrl(e.target.value)}
                      className="mt-1 w-full rounded-lg border border-hcl-border p-2 text-sm text-hcl-navy focus:outline-none focus:ring-2 focus:ring-hcl-blue"
                    />
                  </div>
                </div>

                <div>
                  <label htmlFor="edit-override-reason" className="block text-xs font-semibold text-hcl-muted uppercase">Override Reason</label>
                  <textarea
                    id="edit-override-reason"
                    value={editOverrideReason}
                    onChange={(e) => setEditOverrideReason(e.target.value)}
                    className="mt-1 min-h-20 w-full rounded-lg border border-hcl-border p-2 text-sm text-hcl-navy focus:outline-none focus:ring-2 focus:ring-hcl-blue"
                  />
                </div>

                <div className="flex items-center gap-2 pt-2">
                  <input
                    type="checkbox"
                    id="is_deprecated"
                    checked={editIsDeprecated}
                    onChange={(e) => setEditIsDeprecated(e.target.checked)}
                    className="rounded border-gray-300 text-hcl-blue focus:ring-hcl-blue h-4 w-4"
                  />
                  <label htmlFor="is_deprecated" className="text-xs font-medium text-hcl-navy select-none">
                    Mark component as Deprecated
                  </label>
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-4 border-t">
                <Button variant="outline" onClick={() => setEditingComp(null)} size="sm">
                  Cancel
                </Button>
                <Button onClick={saveComponentEdits} loading={isSavingEdit} size="sm">
                  Save Override
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* DEDUPLICATION REPORT MODAL OVERLAY */}
      {isDedupeModalOpen && dedupeReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4 backdrop-blur-sm">
          <Card className="w-full max-w-2xl bg-white shadow-2xl overflow-y-auto max-h-[90vh] border border-gray-150">
            <CardHeader className="flex flex-row items-center justify-between border-b pb-4">
              <div>
                <CardTitle className="text-lg font-bold text-hcl-navy flex items-center gap-2">
                  <Layers className="h-5 w-5 text-amber-500" />
                  Deduplication Report
                </CardTitle>
                <p className="text-xs text-hcl-muted mt-1">
                  Detailed logs of the Stage 9 component merging process for this SBOM version.
                </p>
              </div>
              <button 
                onClick={() => setIsDedupeModalOpen(false)} 
                className="text-hcl-muted hover:text-hcl-navy p-1 hover:bg-gray-100 rounded-lg transition-colors"
              >
                <X className="h-5 w-5" />
              </button>
            </CardHeader>
            <CardContent className="p-6 space-y-6">
              {/* Summary Stats Grid */}
              <div className="grid grid-cols-2 gap-4">
                <div className="p-4 bg-amber-50/50 border border-amber-100 rounded-xl">
                  <span className="text-xs font-semibold text-amber-700 uppercase tracking-wider">Duplicates Found</span>
                  <div className="text-3xl font-extrabold text-amber-900 mt-1">{dedupeReport.duplicates_found || 0}</div>
                  <p className="text-2xs text-amber-600 mt-1">Identified duplicate component definitions.</p>
                </div>
                <div className="p-4 bg-emerald-50/50 border border-emerald-100 rounded-xl">
                  <span className="text-xs font-semibold text-emerald-700 uppercase tracking-wider">Duplicates Merged</span>
                  <div className="text-3xl font-extrabold text-emerald-900 mt-1">{dedupeReport.duplicates_merged || 0}</div>
                  <p className="text-2xs text-emerald-600 mt-1">Merged duplicate fields into canonical records.</p>
                </div>
              </div>

              {/* Conflict Resolutions Section */}
              <div className="space-y-2">
                <h4 className="text-sm font-bold text-hcl-navy">Conflict Resolutions</h4>
                {dedupeReport.conflicts && dedupeReport.conflicts.length > 0 ? (
                  <div className="border border-hcl-border rounded-xl overflow-hidden">
                    <Table>
                      <TableHead>
                        <tr>
                          <Th className="text-left text-2xs uppercase tracking-wider">Component</Th>
                          <Th className="text-left text-2xs uppercase tracking-wider">Field</Th>
                          <Th className="text-left text-2xs uppercase tracking-wider">Values Found</Th>
                          <Th className="text-left text-2xs uppercase tracking-wider">Selected (Canonical)</Th>
                        </tr>
                      </TableHead>
                      <TableBody>
                        {dedupeReport.conflicts.map((conflict: any, idx: number) => (
                          <tr key={idx} className="hover:bg-gray-50/50 transition-colors">
                            <Td className="font-mono text-xs font-medium text-hcl-navy max-w-[180px] truncate">
                              <span title={conflict.component}>{conflict.component}</span>
                            </Td>
                            <Td>
                              <span className="px-2 py-0.5 text-2xs font-semibold bg-gray-100 text-gray-700 rounded-md">
                                {conflict.field}
                              </span>
                            </Td>
                            <Td className="text-xs text-hcl-muted">
                              {Array.isArray(conflict.values) ? conflict.values.join(' / ') : String(conflict.values)}
                            </Td>
                            <Td className="text-xs font-semibold text-emerald-700 bg-emerald-50/20">
                              {conflict.selected}
                            </Td>
                          </tr>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                ) : (
                  <p className="text-xs text-hcl-muted bg-gray-50/50 p-4 border border-gray-100 rounded-xl">
                    No attribute conflicts occurred. All identical component fields merged automatically and cleanly.
                  </p>
                )}
              </div>

              {/* Reference Mapping Table */}
              <div className="space-y-2">
                <h4 className="text-sm font-bold text-hcl-navy">Reference Mappings (bom-ref / SPDXID)</h4>
                {dedupeReport.ref_mapping && Object.keys(dedupeReport.ref_mapping).length > 0 ? (
                  <div className="border border-hcl-border rounded-xl overflow-hidden max-h-[180px] overflow-y-auto">
                    <Table>
                      <TableHead>
                        <tr>
                          <Th className="text-left text-2xs uppercase tracking-wider">Duplicate Reference</Th>
                          <Th className="w-10">{" "}</Th>
                          <Th className="text-left text-2xs uppercase tracking-wider">Canonical Reference</Th>
                        </tr>
                      </TableHead>
                      <TableBody>
                        {Object.entries(dedupeReport.ref_mapping).map(([dup, canonical]: [string, any], idx: number) => (
                          <tr key={idx} className="hover:bg-gray-50/50 transition-colors">
                            <Td className="font-mono text-xs text-red-600 bg-red-50/10 max-w-[200px] truncate">
                              <span title={dup}>{dup}</span>
                            </Td>
                            <Td className="text-center text-hcl-muted">
                              <ArrowRight className="h-3.5 w-3.5 inline mx-auto" />
                            </Td>
                            <Td className="font-mono text-xs text-emerald-600 bg-emerald-50/10 max-w-[200px] truncate">
                              <span title={canonical}>{canonical}</span>
                            </Td>
                          </tr>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                ) : (
                  <p className="text-xs text-hcl-muted bg-gray-50/50 p-4 border border-gray-100 rounded-xl">
                    No reference mapping is required for this SBOM.
                  </p>
                )}
              </div>

              {/* Action Buttons */}
              <div className="flex justify-end gap-2 pt-4 border-t">
                <Button variant="outline" onClick={() => setIsDedupeModalOpen(false)} size="sm">
                  Close Report
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* ASSIGN PROJECT DIALOG */}
      <Dialog
        open={isAssignModalOpen}
        onClose={() => setIsAssignModalOpen(false)}
        title={sbom.projectid ? "Change Project" : "Assign Project"}
        maxWidth="md"
        footer={
          <div className="flex items-center justify-end gap-2 px-6 py-4">
            <Button size="sm" variant="ghost" onClick={() => setIsAssignModalOpen(false)}>
              Cancel
            </Button>
            <Button size="sm" onClick={handleAssignProjectSubmit} loading={isSavingAssign} disabled={!selectedProjectId}>
              Save Assignment
            </Button>
          </div>
        }
      >
        <DialogBody className="space-y-4">
          {assignError && (
            <div className="rounded-lg border border-red-200 bg-red-50 p-3 text-xs font-medium text-red-800">
              {assignError}
            </div>
          )}
          
          <Select
            label="Project"
            placeholder="Select a project..."
            required
            value={selectedProjectId || ''}
            onChange={(e) => setSelectedProjectId(e.target.value ? Number(e.target.value) : null)}
          >
            {projects?.map((p) => (
              <option key={p.id} value={p.id}>
                {p.project_name}
              </option>
            ))}
          </Select>

          <Input
            label="Change Reason"
            placeholder="e.g. Initial project assignment / migration to new workspace"
            value={assignChangeReason}
            onChange={(e) => setAssignChangeReason(e.target.value)}
          />
        </DialogBody>
      </Dialog>

      {/* EDIT DETAILS DIALOG */}
      <Dialog
        open={isEditDetailsModalOpen}
        onClose={() => setIsEditDetailsModalOpen(false)}
        title="Edit SBOM Details"
        maxWidth="lg"
        footer={
          <div className="flex items-center justify-end gap-2 px-6 py-4">
            <Button size="sm" variant="ghost" onClick={() => setIsEditDetailsModalOpen(false)}>
              Cancel
            </Button>
            <Button size="sm" onClick={handleEditDetailsSubmit} loading={isSavingDetails}>
              Save Details
            </Button>
          </div>
        }
      >
        <DialogBody className="space-y-4">
          {detailsError && (
            <div className="rounded-lg border border-red-200 bg-red-50 p-3 text-xs font-medium text-red-800">
              {detailsError}
            </div>
          )}

          <div className="grid grid-cols-2 gap-4">
            <Input
              label="SBOM Name"
              required
              value={detailName}
              onChange={(e) => setDetailName(e.target.value)}
            />
            <Select
              label="Project"
              placeholder="Select project..."
              value={detailProjectId || ''}
              onChange={(e) => setDetailProjectId(e.target.value ? Number(e.target.value) : null)}
            >
              {projects?.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.project_name}
                </option>
              ))}
            </Select>
          </div>

          <div className="grid grid-cols-3 gap-4">
            <Input
              label="Product Name"
              value={detailProductName}
              onChange={(e) => setDetailProductName(e.target.value)}
            />
            <Input
              label="Product Version"
              value={detailProductVersion}
              onChange={(e) => setDetailProductVersion(e.target.value)}
            />
            <Input
              label="SBOM Version"
              value={detailSbomVersion}
              onChange={(e) => setDetailSbomVersion(e.target.value)}
            />
          </div>

          <Textarea
            label="Description"
            placeholder="Add description..."
            value={detailDescription}
            onChange={(e) => setDetailDescription(e.target.value)}
          />

          <Input
            label="Change Reason"
            placeholder="e.g. Correcting metadata or project workspace"
            value={detailChangeReason}
            onChange={(e) => setDetailChangeReason(e.target.value)}
          />
        </DialogBody>
      </Dialog>
    </div>
  );
}
