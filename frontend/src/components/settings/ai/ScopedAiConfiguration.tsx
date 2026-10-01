'use client';

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@/hooks/useAuth';
import { TopBar } from '@/components/layout/TopBar';
import { Button } from '@/components/ui/Button';
import { AiSettingsPage } from './AiSettingsPage';
import { AiConfigurationScope } from './ConfigurationScope';
import {
  createTenantAiOverride,
  getEffectiveAiConfiguration,
  resetTenantAiOverride,
  type ConfigurationScope,
} from '@/lib/api';

export function ScopedAiConfiguration({ scope }: { scope: ConfigurationScope }) {
  const { activeTenantId } = useAuth();
  return <ConfigurationContent key={`${scope}:${activeTenantId ?? 'platform'}`} scope={scope} />;
}

function ConfigurationContent({ scope }: { scope: ConfigurationScope }) {
  const { hasPermission, activeTenant, activeTenantId, isLoading } = useAuth();
  const key = scope === 'platform' ? 'platform' : `tenant:${activeTenantId}`;
  const allowed = hasPermission(`${scope}:ai:read`) && (scope === 'platform' || Boolean(activeTenantId));
  const canUpdate = hasPermission(`${scope}:ai:update`);
  const canTest = hasPermission(`${scope}:ai:test`);
  const client = useQueryClient();
  const config = useQuery({
    queryKey: ['ai', 'effective-config', key],
    queryFn: ({ signal }) => getEffectiveAiConfiguration(scope, signal),
    enabled: !isLoading && allowed,
  });
  const override = useMutation({
    mutationFn: createTenantAiOverride,
    onSuccess: () => client.invalidateQueries({ queryKey: ['ai'] }),
  });
  const reset = useMutation({
    mutationFn: resetTenantAiOverride,
    onSuccess: () => client.invalidateQueries({ queryKey: ['ai'] }),
  });
  if (isLoading) return <p>Verifying configuration access…</p>;
  if (!allowed) return <p role="alert">Configuration access is not permitted in this context.</p>;
  const tenantName = activeTenant?.name ?? 'this tenant';
  return (
    <div className="flex flex-1 flex-col">
      <TopBar title="AI Configuration" subtitle={scope === 'platform' ? 'Platform defaults' : `Configuration for ${tenantName}`} />
      <main className="mx-auto w-full max-w-4xl space-y-5 p-6">
        {config.isLoading && <p>Loading configuration…</p>}
        {config.error && (
          <div role="alert">
            Unable to load AI configuration.
            <Button variant="ghost" onClick={() => config.refetch()}>Retry</Button>
          </div>
        )}
        {(override.error || reset.error) && <p role="alert">Unable to update the configuration source. Please retry.</p>}
        {config.data && (
          <>
            <section className="space-y-3 rounded-lg border p-4">
              <h2 className="font-semibold">Configuration source</h2>
              <p>{config.data.source === 'TENANT_OVERRIDE' ? 'Tenant override active' : 'Platform default'}</p>
              <p>{scope === 'platform'
                ? 'These defaults apply to tenants without an override.'
                : config.data.override_enabled
                  ? `This configuration applies only to ${tenantName}.`
                  : `${tenantName} is using the platform default.`}</p>
              {config.data.configured_providers.filter(provider => provider.enabled).map((provider, index) => (
                <div key={index}>
                  <p>{provider.provider_name} · {provider.model}</p>
                  <p className="text-sm text-hcl-muted">{provider.credential_present
                    ? scope === 'tenant' && !config.data.override_enabled
                      ? 'Credential managed by platform'
                      : 'Credential configured ✓'
                    : 'No credential configured'}</p>
                </div>
              ))}
              {scope === 'tenant' && canUpdate && (config.data.override_enabled
                ? <Button variant="ghost" loading={reset.isPending} onClick={() => reset.mutate()}>Reset to Platform Default</Button>
                : <Button loading={override.isPending} onClick={() => override.mutate()}>Override for {tenantName}</Button>)}
            </section>
            {canUpdate && (scope === 'platform' || config.data.override_enabled) && (
              <AiConfigurationScope.Provider value={{ scope, key, canTest }}>
                <AiSettingsPage />
              </AiConfigurationScope.Provider>
            )}
          </>
        )}
      </main>
    </div>
  );
}
