'use client';

import { useId } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Select } from '@/components/ui/Select';
import { useAuth } from '@/hooks/useAuth';
import {
  getDashboardApplicationOptions,
  getDashboardProjectOptions,
  getDashboardSbomOptions,
  getVexInvestigationVersions,
  type DashboardFilterScope,
  type DashboardOption,
} from '@/lib/api';

interface Props {
  scope: DashboardFilterScope;
  onChange: (scope: DashboardFilterScope) => void;
  isUpdating: boolean;
  hideClear?: boolean;
  historicalVersions?: boolean;
}

const ALL: DashboardFilterScope = { projectId: null, applicationId: null, sbomId: null };

function idOrNull(value: string): number | null {
  const id = Number(value);
  return value && Number.isSafeInteger(id) && id > 0 ? id : null;
}

function optionElements(items: DashboardOption[], label: 'name' | 'display_name' = 'name') {
  return items.map((item) => (
    <option key={item.id} value={item.id}>{item[label] || item.name}</option>
  ));
}

export function DashboardFilters({ scope, onChange, isUpdating, hideClear = false, historicalVersions = false }: Props) {
  const { activeTenantId } = useAuth();
  const helperId = useId();
  const filtersActive = scope.projectId != null || scope.applicationId != null || scope.sbomId != null;
  const tenantId = activeTenantId ?? '';
  const projects = useQuery({
    queryKey: ['dashboard-projects', tenantId],
    queryFn: ({ signal }) => getDashboardProjectOptions(signal),
    enabled: !!tenantId,
  });
  const applications = useQuery({
    queryKey: ['dashboard-applications', tenantId, scope.projectId],
    queryFn: ({ signal }) => getDashboardApplicationOptions(scope.projectId!, signal),
    enabled: !!tenantId && scope.projectId != null,
  });
  const sboms = useQuery<{items: DashboardOption[]}>({
    queryKey: ['dashboard-sboms', tenantId, scope.projectId, scope.applicationId, historicalVersions],
    queryFn: ({ signal }) => historicalVersions ? getVexInvestigationVersions(scope, signal) : getDashboardSbomOptions(scope, signal),
    enabled: !!tenantId && scope.projectId != null && scope.applicationId != null,
  });

  return (
    <section className="min-w-0 rounded-2xl border border-border bg-surface p-4" aria-label="Dashboard filters">
      <div className="grid min-w-0 grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <Select variant="filter" label="Project" value={scope.projectId ?? ''} disabled={!tenantId || projects.isPending} onChange={(event) => {
          onChange({ projectId: idOrNull(event.target.value), applicationId: null, sbomId: null });
        }}>
          <option value="">All projects</option>
          {optionElements(projects.data?.items ?? [])}
        </Select>
        <Select variant="filter" label="Application" value={scope.applicationId ?? ''}
          disabled={!scope.projectId || applications.isPending}
          title={!scope.projectId ? "Select a project first." : undefined}
          aria-describedby={!scope.projectId ? `${helperId}-project` : undefined}
          onChange={(event) => {
            onChange({ ...scope, applicationId: idOrNull(event.target.value), sbomId: null });
          }}>
          <option value="">All applications</option>
          {optionElements(applications.data?.items ?? [])}
        </Select>
        <Select variant="filter" label="SBOM" value={scope.sbomId ?? ''}
          disabled={!scope.applicationId || sboms.isPending}
          title={!scope.applicationId ? "Select an application first." : undefined}
          aria-describedby={!scope.applicationId ? `${helperId}-application` : undefined}
          onChange={(event) => onChange({ ...scope, sbomId: idOrNull(event.target.value) })}>
          <option value="">All SBOMs</option>
          {optionElements(sboms.data?.items ?? [], 'display_name')}
        </Select>
      </div>
      <span id={`${helperId}-project`} className="sr-only">Select a project first.</span>
      <span id={`${helperId}-application`} className="sr-only">Select an application first.</span>
      {(isUpdating || (!hideClear && filtersActive)) && <div className="mt-3 flex items-center justify-end gap-3">
        {isUpdating && <span role="status" className="text-xs text-hcl-muted">Updating dashboard…</span>}
        {!hideClear && filtersActive && <button
          type="button"
          onClick={() => onChange(ALL)}
          className="rounded-md border border-border px-2.5 py-1 text-xs font-medium text-hcl-blue transition-colors hover:bg-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40"
        >Reset filters</button>}
      </div>}
      {scope.projectId && !applications.isPending && applications.data?.items.length === 0 &&
        <p className="mt-2 text-sm text-hcl-muted">No applications are available in this project.</p>}
      {scope.applicationId && !sboms.isPending && sboms.data?.items.length === 0 &&
        <p className="mt-2 text-sm text-hcl-muted">No SBOMs have been uploaded for this application.</p>}
    </section>
  );
}
