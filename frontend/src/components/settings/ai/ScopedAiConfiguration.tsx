'use client';

import styles from './ai-configuration.module.css';

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { invalidateAiCredentialSurfaces } from '@/lib/queryInvalidation';
import { usePermissions } from '@/hooks/usePermission';
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

export function ScopedAiConfiguration({
  scope,
}: {
  scope: ConfigurationScope;
}) {
  const { activeTenantId } = useAuth();
  return (
    <ConfigurationContent
      key={`${scope}:${activeTenantId ?? 'platform'}`}
      scope={scope}
    />
  );
}

function ConfigurationContent({ scope }: { scope: ConfigurationScope }) {
  const { activeTenant, activeTenantId, isLoading } = useAuth();
  const { can: hasPermission } = usePermissions();
  const key = scope === 'platform' ? 'platform' : `tenant:${activeTenantId}`;
  const allowed =
    hasPermission(`${scope}:ai:read`) &&
    (scope === 'platform' || Boolean(activeTenantId));
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
    onSuccess: () => {
      client.invalidateQueries({ queryKey: ['ai'] });
      invalidateAiCredentialSurfaces(client);
    },
  });
  const reset = useMutation({
    mutationFn: resetTenantAiOverride,
    onSuccess: () => {
      client.invalidateQueries({ queryKey: ['ai'] });
      invalidateAiCredentialSurfaces(client);
    },
  });
  if (isLoading) return <p>Verifying configuration access…</p>;
  if (!allowed)
    return (
      <p role="alert">Configuration access is not permitted in this context.</p>
    );
  const tenantName = activeTenant?.name ?? 'this tenant';
  return (
    <div className={`${styles.page} flex min-w-0 flex-1 flex-col`}>
      <TopBar
        title="AI Configuration"
        subtitle={
          scope === 'platform'
            ? 'Configure platform AI providers, models and defaults.'
            : `Configuration for ${tenantName}`
        }
        breadcrumbs={
          scope === 'platform'
            ? [
                { label: 'Platform', href: '/platform' },
                { label: 'Configuration' },
                { label: 'AI Configuration' },
              ]
            : undefined
        }
      />
      <div className="w-full min-w-0 space-y-6 p-4 md:p-6 2xl:p-8">
        {config.isLoading && <p>Loading configuration…</p>}
        {config.error && (
          <div role="alert">
            Unable to load AI configuration.
            <Button variant="ghost" onClick={() => config.refetch()}>
              Retry
            </Button>
          </div>
        )}
        {(override.error || reset.error) && (
          <p role="alert">
            Unable to update the configuration source. Please retry.
          </p>
        )}
        {config.data && (
          <>
            {scope === 'tenant' && (
              <section className="space-y-3 rounded-xl border border-border bg-surface p-5">
                <h2 className="font-semibold">Configuration source</h2>
                <p>
                  {config.data.source === 'TENANT_OVERRIDE'
                    ? 'Tenant override active'
                    : 'Platform default'}
                </p>
                <p>
                  {config.data.override_enabled
                    ? `This configuration applies only to ${tenantName}.`
                    : `${tenantName} is using the platform default.`}
                </p>
                {config.data.configured_providers
                  .filter((provider) => provider.enabled)
                  .map((provider, index) => (
                    <div key={index}>
                      <p>
                        {provider.provider_name} · {provider.model}
                      </p>
                      <p className="text-sm text-hcl-muted">
                        {provider.credential_present
                          ? !config.data.override_enabled
                            ? 'Credential managed by platform'
                            : 'Credential configured ✓'
                          : 'No credential configured'}
                      </p>
                    </div>
                  ))}
                {canUpdate &&
                  (config.data.override_enabled ? (
                    <Button
                      variant="ghost"
                      loading={reset.isPending}
                      onClick={() => reset.mutate()}
                    >
                      Reset to Platform Default
                    </Button>
                  ) : (
                    <Button
                      loading={override.isPending}
                      onClick={() => override.mutate()}
                    >
                      Override for {tenantName}
                    </Button>
                  ))}
              </section>
            )}
            {(scope === 'platform' ||
              (canUpdate && config.data.override_enabled)) && (
              <AiConfigurationScope.Provider
                value={{ scope, key, canTest, canUpdate }}
              >
                <AiSettingsPage effective={config.data} />
              </AiConfigurationScope.Provider>
            )}
          </>
        )}
      </div>
    </div>
  );
}
