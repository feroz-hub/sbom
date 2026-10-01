'use client';

import { useAuth } from '@/hooks/useAuth';
import { TopBar } from '@/components/layout/TopBar';
import { LifecycleProviderSettings } from './LifecycleProviderSettings';
import type { ConfigurationScope } from '@/lib/api';

export function ScopedLifecycleConfiguration({ scope }: { scope: ConfigurationScope }) {
  const { activeTenantId, activeTenant, hasPermission, isLoading } = useAuth();
  const key = scope === 'platform' ? 'platform' : `tenant:${activeTenantId}`;
  if (isLoading) return <p>Verifying configuration access…</p>;
  if (!hasPermission(`${scope}:lifecycle-provider:read`) || (scope === 'tenant' && !activeTenantId)) return <p role="alert">Configuration access is not permitted in this context.</p>;
  return <div className="flex flex-1 flex-col"><TopBar title="Lifecycle Providers" subtitle={scope === 'platform' ? 'Platform defaults' : `Configuration for ${activeTenant?.name ?? 'this tenant'}`} /><main className="mx-auto w-full max-w-7xl space-y-4 p-6">
    <p>{scope === 'platform' ? 'Manage default providers for inheriting tenants.' : 'Each provider independently inherits the platform default unless overridden for this tenant.'}</p>
    <LifecycleProviderSettings key={key} scope={scope} scopeKey={key} tenantName={activeTenant?.name ?? 'this tenant'} canUpdate={hasPermission(`${scope}:lifecycle-provider:update`)} canTest={hasPermission(`${scope}:lifecycle-provider:test`)} canSync={hasPermission(`${scope}:lifecycle-provider:sync`)} />
  </main></div>;
}
