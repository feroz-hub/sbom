'use client';

import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { useEffect, useMemo, useState } from 'react';
import { Play, ArrowLeft, ExternalLink, Edit2, GitBranch, History, Layers, Download, Check, RefreshCw, Eye, ArrowRight, X } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { StatusBadge } from '@/components/ui/Badge';
import { Table, TableHead, TableBody, Th, SortableTh, Td, EmptyRow } from '@/components/ui/Table';
import { SkeletonRow } from '@/components/ui/Spinner';
import { Pagination } from '@/components/ui/Pagination';
import { AnalysisProgress } from '@/components/analysis/AnalysisProgress';
import { ScheduleCard } from '@/components/schedules/ScheduleCard';
import { ValidationReportSection } from '@/components/sboms/ValidationReportSection';
import { 
  getSbomComponents, 
  getRuns, 
  getSbomInfo, 
  getSbomRiskSummary, 
  getSbomValidationReport,
  editSbom,
  getSbomVersions,
  compareSbomVersions,
  restoreSbomVersion,
  BASE_URL
} from '@/lib/api';
import { useAnalysisStream } from '@/hooks/useAnalysisStream';
import { invalidateAnalysisCompletion } from '@/lib/queryInvalidation';
import { useTableSort } from '@/hooks/useTableSort';
import { usePagination } from '@/hooks/usePagination';
import { formatDate, formatDuration } from '@/lib/utils';
import type { SBOMSource, SBOMComponent, AnalysisRun } from '@/types';

type ComponentSortKey = 'name' | 'version' | 'component_type' | 'license' | 'lifecycle_status';
type RunSortKey = 'id' | 'run_status' | 'total_findings' | 'duration_ms' | 'started_on';

interface SbomDetailProps {
  sbom: SBOMSource;
}

export function SbomDetail({ sbom }: SbomDetailProps) {
  const router = useRouter();
  const queryClient = useQueryClient();
  const { state, startAnalysis, cancel, reset } = useAnalysisStream(sbom.id);
  const [activeTab, setActiveTab] = useState<'overview' | 'components' | 'versions' | 'runs'>('overview');
  
  // Edit Component State
  const [editingComp, setEditingComp] = useState<SBOMComponent | null>(null);
  const [editName, setEditName] = useState('');
  const [editVersion, setEditVersion] = useState('');
  const [editSupplier, setEditSupplier] = useState('');
  const [editLicense, setEditLicense] = useState('');
  const [editHashes, setEditHashes] = useState('');
  const [editLifecycleStatus, setEditLifecycleStatus] = useState('active');
  const [editEosDate, setEditEosDate] = useState('');
  const [editEolDate, setEditEolDate] = useState('');
  const [editIsDeprecated, setEditIsDeprecated] = useState(false);
  const [editMaintStatus, setEditMaintStatus] = useState('active');
  const [isSavingEdit, setIsSavingEdit] = useState(false);
  const [editError, setEditError] = useState('');

  // Version Comparison State
  const [selectedVersions, setSelectedVersions] = useState<number[]>([]);
  const [compareData, setCompareData] = useState<any>(null);
  const [isComparing, setIsComparing] = useState(false);
  const [restoreMessage, setRestoreMessage] = useState('');

  const { data: components, isLoading: compLoading } = useQuery({
    queryKey: ['sbom-components', sbom.id],
    queryFn: ({ signal }) => getSbomComponents(sbom.id, signal),
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

  // 8-stage validation report
  const { data: validationReport } = useQuery({
    queryKey: ['sbom-validation-report', sbom.id],
    queryFn: ({ signal }) => getSbomValidationReport(sbom.id, signal),
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

  // Components table: in-memory sort + paginate
  const componentRows = useMemo<SBOMComponent[]>(() => components ?? [], [components]);
  const componentSortAccessors = useMemo(
    () => ({
      name: (c: SBOMComponent) => (c.name ?? '').toLowerCase(),
      version: (c: SBOMComponent) => c.version ?? '',
      component_type: (c: SBOMComponent) => (c.component_type ?? '').toLowerCase(),
      license: (c: SBOMComponent) => (c.license ?? '').toLowerCase(),
      lifecycle_status: (c: SBOMComponent) => (c.lifecycle_status ?? '').toLowerCase(),
    }),
    [],
  );
  const {
    sort: compSort,
    sortedRows: sortedComponents,
    toggle: toggleCompSort,
  } = useTableSort<SBOMComponent, ComponentSortKey>(componentRows, componentSortAccessors, {
    initialKey: 'name',
    initialDirection: 'asc',
  });
  const compPagination = usePagination<SBOMComponent>(sortedComponents, {
    defaultPageSize: 25,
    storageKey: 'sbom-components',
  });

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
    compPagination.resetPage();
  }, [components?.length]);

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

  // Handle opening edit modal
  const openEditModal = (c: SBOMComponent) => {
    setEditingComp(c);
    setEditName(c.name || '');
    setEditVersion(c.version || '');
    setEditSupplier(c.supplier || '');
    setEditLicense(c.license || '');
    setEditHashes(c.hashes || '');
    setEditLifecycleStatus(c.lifecycle_status || 'active');
    setEditEosDate(c.eos_date || '');
    setEditEolDate(c.eol_date || '');
    setEditIsDeprecated(c.is_deprecated || false);
    setEditMaintStatus(c.maintenance_status || 'active');
    setEditError('');
  };

  // Handle saving edit
  const saveComponentEdits = async () => {
    if (!editingComp) return;
    setIsSavingEdit(true);
    setEditError('');
    try {
      const payload = {
        metadata: null,
        components: [
          {
            bom_ref: editingComp.bom_ref || editingComp.name,
            name: editName,
            version: editVersion,
            supplier: editSupplier,
            license: editLicense,
            hashes: editHashes,
            lifecycle: {
              lifecycle_status: editLifecycleStatus,
              eos_date: editEosDate || null,
              eol_date: editEolDate || null,
              is_deprecated: editIsDeprecated,
              maintenance_status: editMaintStatus,
            }
          }
        ],
        change_summary: `Manual override for ${editingComp.name} (${editVersion})`
      };

      const newVersion = await editSbom(sbom.id, payload, sbom.created_by ?? undefined);
      
      // Invalidate queries to reload details, components, versions
      queryClient.invalidateQueries({ queryKey: ['sbom', sbom.id] });
      queryClient.invalidateQueries({ queryKey: ['sbom-components', sbom.id] });
      queryClient.invalidateQueries({ queryKey: ['sbom-versions', sbom.id] });
      setEditingComp(null);
      router.push(`/sboms/${newVersion.id}`);
    } catch (err: any) {
      setEditError(err.message || 'Failed to apply modifications.');
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
      queryClient.invalidateQueries({ queryKey: ['sbom', sbom.id] });
      queryClient.invalidateQueries({ queryKey: ['sbom-components', sbom.id] });
      queryClient.invalidateQueries({ queryKey: ['sbom-versions', sbom.id] });
      setTimeout(() => {
        setRestoreMessage('');
        router.push(`/sboms/${restoredVersion.id}`);
      }, 2000);
    } catch (err: any) {
      setRestoreMessage(`Restoration failed: ${err.message}`);
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
          <ValidationReportSection report={validationReport} />
        </div>
      )}

      {/* SBOM Tab List Navigation */}
      <div className="flex border-b border-hcl-border gap-6">
        {[
          { id: 'overview', label: 'Overview & Risk', icon: Eye },
          { id: 'components', label: 'Components List', icon: Layers },
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
                <a
                  href={`${BASE_URL}/api/sboms/${sbom.id}/export`}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-hcl-border text-xs font-semibold hover:bg-hcl-light transition-colors text-hcl-navy"
                  download
                >
                  <Download className="h-3.5 w-3.5" /> Export CycloneDX
                </a>
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
                  { label: 'Format / Type', value: sbom.sbom_type || '—' },
                  { label: 'SBOM Version', value: sbom.sbom_version || '1.0.0' },
                  { label: 'Product Version', value: sbom.productver || '—' },
                  { label: 'Project ID', value: sbom.projectid ? `#${sbom.projectid}` : '—' },
                  { label: 'Created By', value: sbom.created_by || '—' },
                  { label: 'Created On', value: formatDate(sbom.created_on) },
                  { label: 'Updated On', value: formatDate(sbom.modified_on) },
                ].map(({ label, value }) => (
                  <div key={label}>
                    <dt className="text-xs font-medium text-hcl-muted uppercase tracking-wide">{label}</dt>
                    <dd className="mt-1 text-sm font-medium text-hcl-navy break-words">{value}</dd>
                  </div>
                ))}
              </dl>
            </CardContent>
          </Card>

          <ScheduleCard scope="SBOM" targetId={sbom.id} />

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
                    <dd className="mt-1 text-sm font-medium text-hcl-navy">{info.component_count.toLocaleString()}</dd>
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
        </div>
      )}

      {/* TAB 2: COMPONENTS */}
      {activeTab === 'components' && (
        <Card>
          <CardHeader>
            <CardTitle>
              Components{' '}
              {components && <span className="ml-2 text-sm font-normal text-hcl-muted">({components.length})</span>}
            </CardTitle>
          </CardHeader>
          <div className="overflow-hidden">
            <Table striped ariaLabel="SBOM components">
              <TableHead>
                <tr>
                  <SortableTh sortKey="name" activeKey={compSort.key} direction={compSort.direction} onToggle={(k) => toggleCompSort(k as ComponentSortKey)}>Name</SortableTh>
                  <SortableTh sortKey="version" activeKey={compSort.key} direction={compSort.direction} onToggle={(k) => toggleCompSort(k as ComponentSortKey)}>Version</SortableTh>
                  <SortableTh sortKey="component_type" activeKey={compSort.key} direction={compSort.direction} onToggle={(k) => toggleCompSort(k as ComponentSortKey)}>Type</SortableTh>
                  <SortableTh sortKey="license" activeKey={compSort.key} direction={compSort.direction} onToggle={(k) => toggleCompSort(k as ComponentSortKey)}>License</SortableTh>
                  <SortableTh sortKey="lifecycle_status" activeKey={compSort.key} direction={compSort.direction} onToggle={(k) => toggleCompSort(k as ComponentSortKey)}>Lifecycle</SortableTh>
                  <Th className="text-right">Actions</Th>
                </tr>
              </TableHead>
              <TableBody>
                {compLoading ? (
                  Array.from({ length: 5 }).map((_, i) => <SkeletonRow key={i} cols={6} />)
                ) : !components?.length ? (
                  <EmptyRow cols={6} message="No components found for this SBOM" />
                ) : (
                  compPagination.pageItems.map((c) => (
                    <tr key={c.id} className="hover:bg-hcl-light/40">
                      <Td className="font-medium text-hcl-navy">{c.name}</Td>
                      <Td className="font-mono text-xs">{c.version || '—'}</Td>
                      <Td className="text-hcl-muted">{c.component_type || '—'}</Td>
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
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold capitalize border ${
                          c.lifecycle_status === 'eol' || c.lifecycle_status === 'unsupported'
                            ? 'bg-red-50 text-red-700 border-red-200'
                            : c.lifecycle_status === 'eos' || c.lifecycle_status === 'deprecated'
                            ? 'bg-amber-50 text-amber-700 border-amber-200'
                            : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                        }`}>
                          {c.lifecycle_status || 'active'}
                        </span>
                      </Td>
                      <Td className="text-right">
                        <button
                          onClick={() => openEditModal(c)}
                          className="inline-flex items-center gap-1 text-xs text-hcl-blue hover:text-hcl-navy transition-colors font-medium"
                        >
                          <Edit2 className="h-3 w-3" /> Edit
                        </button>
                      </Td>
                    </tr>
                  ))
                )}
              </TableBody>
            </Table>
            {!compLoading && componentRows.length > 0 ? (
              <Pagination
                page={compPagination.page}
                pageSize={compPagination.pageSize}
                total={compPagination.total}
                totalPages={compPagination.totalPages}
                rangeStart={compPagination.rangeStart}
                rangeEnd={compPagination.rangeEnd}
                hasPrev={compPagination.hasPrev}
                hasNext={compPagination.hasNext}
                onPageChange={compPagination.setPage}
                onPageSizeChange={compPagination.setPageSize}
                itemNoun="component"
              />
            ) : null}
          </div>
        </Card>
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
                              title="Export CycloneDX"
                              download
                            >
                              <Download className="h-3.5 w-3.5" />
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
                    <label className="block text-xs font-semibold text-hcl-muted uppercase">Lifecycle Status</label>
                    <select
                      value={editLifecycleStatus}
                      onChange={(e) => setEditLifecycleStatus(e.target.value)}
                      className="mt-1 w-full rounded-lg border border-hcl-border p-2 text-sm text-hcl-navy focus:outline-none focus:ring-2 focus:ring-hcl-blue"
                    >
                      <option value="active">Active</option>
                      <option value="deprecated">Deprecated</option>
                      <option value="eos">End of Support (EOS)</option>
                      <option value="eol">End of Life (EOL)</option>
                      <option value="unsupported">Unsupported</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-hcl-muted uppercase">Maintenance Status</label>
                    <select
                      value={editMaintStatus}
                      onChange={(e) => setEditMaintStatus(e.target.value)}
                      className="mt-1 w-full rounded-lg border border-hcl-border p-2 text-sm text-hcl-navy focus:outline-none focus:ring-2 focus:ring-hcl-blue"
                    >
                      <option value="active">Active / Maintained</option>
                      <option value="unmaintained">Unmaintained</option>
                    </select>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-semibold text-hcl-muted uppercase">EOS Date</label>
                    <input
                      type="text"
                      placeholder="YYYY-MM-DD"
                      value={editEosDate}
                      onChange={(e) => setEditEosDate(e.target.value)}
                      className="mt-1 w-full rounded-lg border border-hcl-border p-2 text-sm text-hcl-navy focus:outline-none focus:ring-2 focus:ring-hcl-blue"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-hcl-muted uppercase">EOL Date</label>
                    <input
                      type="text"
                      placeholder="YYYY-MM-DD"
                      value={editEolDate}
                      onChange={(e) => setEditEolDate(e.target.value)}
                      className="mt-1 w-full rounded-lg border border-hcl-border p-2 text-sm text-hcl-navy focus:outline-none focus:ring-2 focus:ring-hcl-blue"
                    />
                  </div>
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
    </div>
  );
}
