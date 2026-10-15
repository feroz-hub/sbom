'use client';

import { usePermissions } from '@/hooks/usePermission';
import { useAuth } from '@/hooks/useAuth';
import { TopBar } from '@/components/layout/TopBar';
import { Badge } from '@/components/ui/Badge';
import { GitBranch, ShieldCheck } from 'lucide-react';
import { LifecycleProviderSettings } from './LifecycleProviderSettings';
import type { ConfigurationScope } from '@/lib/api';

export function ScopedLifecycleConfiguration({ scope }: { scope: ConfigurationScope }) {
  const { activeTenantId, activeTenant, isLoading } = useAuth();
  const { can: hasPermission } = usePermissions();
  const key = scope === 'platform' ? 'platform' : `tenant:${activeTenantId}`;
  if (isLoading) return <p>Verifying configuration access…</p>;
  if (!hasPermission(`${scope}:lifecycle-provider:read`) || (scope === 'tenant' && !activeTenantId)) return <p role="alert">Configuration access is not permitted in this context.</p>;
  return <div className="flex min-w-0 flex-1 flex-col"><TopBar title="Lifecycle Providers" subtitle="Manage component lifecycle intelligence sources and their operational configuration." /><section aria-label="Lifecycle provider configuration" className="mx-auto w-full min-w-0 max-w-7xl space-y-5 p-4 sm:p-6">
    <section aria-label="Configuration scope" className="flex flex-col gap-3 rounded-xl border border-border bg-surface px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex min-w-0 items-start gap-3">{scope === 'platform' ? <ShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-hcl-muted" /> : <GitBranch className="mt-0.5 h-5 w-5 shrink-0 text-hcl-muted" />}<div className="min-w-0"><div className="mb-1"><Badge variant="gray" className="max-w-full"><span className="truncate" title={scope === 'platform' ? 'Platform defaults' : activeTenant?.name ?? 'this tenant'}>{scope === 'platform' ? 'Platform defaults' : `Tenant configuration · ${activeTenant?.name ?? 'this tenant'}`}</span></Badge></div><p className="text-xs leading-relaxed text-hcl-muted">{scope === 'platform' ? 'Changes apply to tenants inheriting these providers. Existing tenant overrides retain their own configuration.' : 'Providers inherit platform settings unless customized here. Tenant overrides are marked in the directory.'}</p></div></div>
      <a href="#lifecycle-help" className="shrink-0 text-xs font-medium text-hcl-blue underline-offset-4 hover:underline focus-visible:rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue">About lifecycle sources</a>
    </section>
    <LifecycleProviderSettings key={key} scope={scope} scopeKey={key} tenantName={activeTenant?.name ?? 'this tenant'} canUpdate={hasPermission(`${scope}:lifecycle-provider:update`)} canTest={hasPermission(`${scope}:lifecycle-provider:test`)} canSync={hasPermission(`${scope}:lifecycle-provider:sync`)} />
    <p id="lifecycle-help" tabIndex={-1} className="text-xs leading-relaxed text-hcl-muted">Lifecycle sources provide different kinds of evidence. Vulnerability advisories, registry deprecation and repository activity do not independently prove end of life. Review each provider’s coverage and verification details before enabling it.</p>
  </section></div>;
}
