'use client';

import { useQuery } from '@tanstack/react-query';
import { Select } from '@/components/ui/Select';
import { useAuth } from '@/hooks/useAuth';
import {
  getDashboardApplicationOptions,
  getDashboardProjectOptions,
  getDashboardSbomOptions,
  listPlatformTenants,
  type DashboardFilterScope,
  type DashboardOption,
} from '@/lib/api';

interface Props {
  scope: DashboardFilterScope;
  onChange: (scope: DashboardFilterScope) => void;
  isUpdating: boolean;
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

export function DashboardFilters({ scope, onChange, isUpdating }: Props) {
  const { activeTenant, activeTenantId, availableTenants, selectTenant, user } = useAuth();
  const tenantId = activeTenantId ?? '';
  // Platform administrators can select tenants without holding a membership.
  // The auth context intentionally lists memberships/current tenant only;
  // share the platform list query with the sidebar tenant switcher.
  const platformTenants = useQuery({
    queryKey: ['platform-tenants'],
    queryFn: listPlatformTenants,
    enabled: Boolean(user?.isPlatformAdmin),
    staleTime: 60_000,
    retry: false,
  });
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
  const sboms = useQuery({
    queryKey: ['dashboard-sboms', tenantId, scope.projectId, scope.applicationId],
    queryFn: ({ signal }) => getDashboardSbomOptions(scope, signal),
    enabled: !!tenantId && scope.projectId != null && scope.applicationId != null,
  });

  const project = projects.data?.items.find((item) => item.id === scope.projectId);
  const application = applications.data?.items.find((item) => item.id === scope.applicationId);
  const sbom = sboms.data?.items.find((item) => item.id === scope.sbomId);
  const tenants = (user?.isPlatformAdmin && platformTenants.data
    ? platformTenants.data : availableTenants
  ).filter((item) => item.status === 'ACTIVE');

  return (
    <section className="rounded-xl border border-border bg-surface p-4" aria-label="Dashboard filters">
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Select label="Tenant" value={tenantId} onChange={(event) => {
          onChange(ALL);
          void selectTenant(event.target.value);
        }}>
          {tenants.map((tenant) => <option key={tenant.id} value={tenant.id}>{tenant.name}</option>)}
        </Select>
        <Select label="Project" value={scope.projectId ?? ''} disabled={!tenantId || projects.isPending} onChange={(event) => {
          onChange({ projectId: idOrNull(event.target.value), applicationId: null, sbomId: null });
        }}>
          <option value="">ALL</option>
          {optionElements(projects.data?.items ?? [])}
        </Select>
        <Select label="Application" value={scope.applicationId ?? ''}
          disabled={!scope.projectId || applications.isPending}
          hint={!scope.projectId ? 'Select a project to filter by application.' : undefined}
          onChange={(event) => {
            onChange({ ...scope, applicationId: idOrNull(event.target.value), sbomId: null });
          }}>
          <option value="">ALL</option>
          {optionElements(applications.data?.items ?? [])}
        </Select>
        <Select label="SBOM" value={scope.sbomId ?? ''}
          disabled={!scope.applicationId || sboms.isPending}
          onChange={(event) => onChange({ ...scope, sbomId: idOrNull(event.target.value) })}>
          <option value="">ALL</option>
          {optionElements(sboms.data?.items ?? [], 'display_name')}
        </Select>
      </div>
      <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs text-hcl-muted" aria-live="polite">
          Viewing: {[activeTenant?.name || 'Tenant', project?.name, application?.name, sbom?.version ? `v${sbom.version}` : sbom?.name]
            .filter(Boolean).join(' › ')}
          {isUpdating ? ' · Updating dashboard…' : ''}
        </p>
        <button
          type="button"
          onClick={() => onChange(ALL)}
          disabled={!scope.projectId && !scope.applicationId && !scope.sbomId}
          className="rounded-md border border-border px-2.5 py-1 text-xs font-medium text-hcl-blue transition-colors hover:bg-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40 disabled:cursor-default disabled:opacity-50"
        >
          Clear all filters
        </button>
      </div>
      {scope.projectId && !applications.isPending && applications.data?.items.length === 0 &&
        <p className="mt-2 text-sm text-hcl-muted">No applications are available in this project.</p>}
      {scope.applicationId && !sboms.isPending && sboms.data?.items.length === 0 &&
        <p className="mt-2 text-sm text-hcl-muted">No SBOMs have been uploaded for this application.</p>}
    </section>
  );
}
