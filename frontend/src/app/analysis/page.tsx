'use client';

import Link from 'next/link';
import { Suspense, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { TopBar } from '@/components/layout/TopBar';
import { Select } from '@/components/ui/Select';
import { PageSpinner } from '@/components/ui/Spinner';
import { Alert } from '@/components/ui/Alert';
import { AnalysisHubTabs } from '@/components/analysis/AnalysisHubTabs';
import { AnalysisRunsHistory } from '@/components/analysis/AnalysisRunsHistory';
import { RunsTable } from '@/components/analysis/RunsTable';
import { ConsolidatedAnalysisPanel, type SourceKey } from '@/components/analysis/ConsolidatedAnalysisPanel';
import { VulnerabilitiesByScope } from '@/components/analysis/VulnerabilitiesByScope';
import { getRuns, getProjects, getAnalysisConfig } from '@/lib/api';
import { recordIdLabel } from '@/lib/recordDisplay';
import { useAnalysisUrlState } from '@/hooks/useAnalysisUrlState';
import { useSbomsList } from '@/hooks/useSbomsList';
import { useAuth } from '@/hooks/useAuth';

function AnalysisPageInner() {
  const { activeTenantId } = useAuth();
  const state = useAnalysisUrlState();
  const { projectFilter, productFilter, sbomFilter, hubTab } = state;
  const [selectedSources, setSelectedSources] = useState<SourceKey[]>(['NVD', 'OSV']);
  const projects = useQuery({ queryKey: ['projects', 'analysis', activeTenantId], queryFn: ({ signal }) => getProjects(signal) });
  const sboms = useSbomsList();
  const config = useQuery({ queryKey: ['analysis-config', activeTenantId], queryFn: ({ signal }) => getAnalysisConfig(signal), enabled: hubTab === 'consolidated', staleTime: 60_000 });
  const scope = { project_id: projectFilter || undefined, product_id: productFilter || undefined, sbom_id: sbomFilter || undefined };
  const recent = useQuery({
    queryKey: ['runs', 'consolidated-recent', activeTenantId, scope],
    queryFn: ({ signal }) => getRuns({ ...scope, page: 1, page_size: 5, summary_only: true }, signal),
    enabled: hubTab === 'consolidated',
  });
  const products = useMemo(() => {
    const byId = new Map<string, string>();
    for (const sbom of sboms.data ?? []) {
      if (hubTab === 'consolidated' && projectFilter && String(sbom.projectid ?? sbom.project_id) !== projectFilter) continue;
      if (sbom.product_id != null) byId.set(String(sbom.product_id), sbom.product_name?.trim() || recordIdLabel('Application', sbom.product_display_id));
    }
    return [...byId].map(([id, name]) => ({ id, name })).sort((a, b) => a.name.localeCompare(b.name));
  }, [sboms.data, projectFilter, hubTab]);
  const scanSboms = (sboms.data ?? []).filter(sbom => (!projectFilter || String(sbom.projectid ?? sbom.project_id) === projectFilter)
    && (!productFilter || String(sbom.product_id) === productFilter));
  const scopeControls = <div className="grid min-w-0 gap-3 sm:grid-cols-2">
    <Select label="Project" aria-label="Project" value={projectFilter} onChange={event => hubTab === 'consolidated' ? state.setScanScope(event.target.value, '', '') : state.setProjectFilter(event.target.value)}>
      <option value="">All projects</option>{projects.data?.map(project => <option key={project.id} value={project.id}>{project.project_name}</option>)}
    </Select>
    <Select label="Product / Application" aria-label="Product / Application" value={productFilter} onChange={event => hubTab === 'consolidated' ? state.setScanScope(projectFilter, event.target.value, '') : state.setProductFilter(event.target.value)}>
      <option value="">All products / applications</option>{products.map(product => <option key={product.id} value={product.id}>{product.name}</option>)}
    </Select>
  </div>;
  return <div className="flex min-w-0 flex-1 flex-col">
    <TopBar title={hubTab === 'consolidated' ? 'Consolidated Analysis' : hubTab === 'vulnerabilities' ? 'Analysis Vulnerabilities' : 'Analysis Runs'}
      subtitle={hubTab === 'consolidated' ? 'Multi-source vulnerability analysis across supported databases.' : hubTab === 'runs' ? 'Review analysis history, investigate findings and compare results.' : 'Review findings across the selected portfolio scope.'} />
    <div className="min-w-0 space-y-5 p-4 md:p-6">
      <AnalysisHubTabs active={hubTab} onChange={state.setHubTab} />
      {hubTab === 'consolidated' && <div role="tabpanel" id="analysis-panel-consolidated" aria-labelledby="analysis-tab-consolidated" className="space-y-5">
        <ConsolidatedAnalysisPanel key={activeTenantId} analysisConfig={config.data} sboms={scanSboms} scopeControls={scopeControls}
          isLoading={config.isLoading || sboms.isLoading || projects.isLoading} error={config.error || sboms.error || projects.error}
          onRetry={() => { void config.refetch(); void sboms.refetch(); void projects.refetch(); }}
          consolidatedSbomId={sbomFilter} onConsolidatedSbomIdChange={state.setSbomFilter}
          selectedSources={selectedSources} onSelectedSourcesChange={setSelectedSources}
          onComplete={() => { void recent.refetch(); }} />
        <section aria-label="Recent runs" className="min-w-0 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2"><div><h2 className="text-base font-semibold text-hcl-navy">Recent runs</h2><p className="mt-1 text-xs text-hcl-muted">Up to five latest runs in this scope.</p></div>
            <Link className="text-sm font-medium text-primary underline" href={`/analysis?${new URLSearchParams({ tab: 'runs', ...(projectFilter ? { project: projectFilter } : {}), ...(productFilter ? { product: productFilter } : {}), ...(sbomFilter ? { sbom: sbomFilter } : {}) })}`}>View all runs</Link></div>
          <RunsTable compact runs={recent.data} isLoading={recent.isLoading} error={recent.error} onRetry={() => { void recent.refetch(); }} />
        </section>
      </div>}
      {hubTab === 'runs' && <div role="tabpanel" id="analysis-panel-runs" aria-labelledby="analysis-tab-runs" className="min-w-0 space-y-4">
        <div className="space-y-3 rounded-xl border border-border bg-surface p-4">
          <div className="grid gap-3 lg:grid-cols-3 lg:items-end"><div className="lg:col-span-2">{scopeControls}</div><Select label="SBOM" aria-label="SBOM" value={sbomFilter} onChange={event => state.setSbomFilter(event.target.value)}>
            <option value="">All SBOMs</option>{sboms.data?.map(sbom => <option key={sbom.id} value={sbom.id}>{sbom.sbom_name}{sbom.sbom_version ? ` · ${sbom.sbom_version}` : ''}</option>)}
          </Select></div>
          {(projectFilter || productFilter || sbomFilter) && <button type="button" className="text-sm text-primary underline" onClick={state.clearFilters}>Clear scope filters</button>}
          {(projects.error || sboms.error) && <Alert variant="error">Could not load scope choices. Existing history remains available.</Alert>}
        </div>
        <AnalysisRunsHistory key={`${activeTenantId}:${projectFilter}:${productFilter}:${sbomFilter}`} scope={scope} status={state.statusFilter} onStatusChange={state.setStatusFilter} />
      </div>}
      {hubTab === 'vulnerabilities' && <div role="tabpanel" id="analysis-panel-vulnerabilities" aria-labelledby="analysis-tab-vulnerabilities">
        <VulnerabilitiesByScope severity={state.severityFilter} onSeverityChange={state.setSeverityFilter} scope={projectFilter ? {
          projectId: projectFilter || null, applicationId: productFilter || null, sbomId: productFilter && sbomFilter ? sbomFilter : null,
        } : undefined} />
      </div>}
    </div>
  </div>;
}

export default function AnalysisPage() {
  return <Suspense fallback={<div className="flex flex-1 flex-col"><TopBar title="Analysis" /><div className="p-12"><PageSpinner /></div></div>}><AnalysisPageInner /></Suspense>;
}
