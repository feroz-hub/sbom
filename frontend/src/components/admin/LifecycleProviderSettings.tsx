'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { RefreshCw, Settings, TestTube2 } from 'lucide-react';
import { PermissionButton as Button } from '@/components/ui/PermissionButton';
import { Badge } from '@/components/ui/Badge';
import { ProviderHealthBadge } from './ProviderHealthBadge';
import { LifecycleProviderForm } from './LifecycleProviderForm';
import { useMutationScope } from '@/hooks/useMutationScope';
import { invalidateLifecycleProviderSurfaces } from '@/lib/queryInvalidation';
import { useToast } from '@/hooks/useToast';
import { getApiErrorMessage, normalizeNotificationMessage } from '@/lib/notifications';
import {
  deleteLifecycleProviderSecret,
  resetLifecycleProviderOverride,
  type ConfigurationScope,
  listLifecycleProviders,
  setLifecycleProviderSecret,
  syncLifecycleProvider,
  testLifecycleProvider,
  updateLifecycleProvider,
} from '@/lib/api';
import { formatDate } from '@/lib/utils';
import type { LifecycleProviderConfig, LifecycleProviderTestResult, LifecycleProviderUpdatePayload } from '@/types';

export function LifecycleProviderSettings({ scope = 'tenant', scopeKey = 'tenant', tenantName = 'this tenant', canUpdate = true, canTest = true, canSync = true }: { scope?: ConfigurationScope; scopeKey?: string; tenantName?: string; canUpdate?: boolean; canTest?: boolean; canSync?: boolean }) {
  const queryClient = useQueryClient();
  const { showToast } = useToast();
  const mutationScope = useMutationScope();
  const [editing, setEditing] = useState<LifecycleProviderConfig | null>(null);
  const [testResult, setTestResult] = useState<Record<string, LifecycleProviderTestResult>>({});

  const providersQuery = useQuery({
    queryKey: ['lifecycle-providers', scopeKey],
    queryFn: ({ signal }) => listLifecycleProviders(signal, scope),
    staleTime: 30_000,
  });

  const invalidate = (readiness = true) => invalidateLifecycleProviderSurfaces(queryClient, scopeKey, { readiness });
  const persistsHealth = (key: string) => scope === 'platform' || providersQuery.data?.find(provider => provider.provider_key === key)?.override_enabled === true;

  const updateMutation = useMutation({
    onMutate: () => mutationScope.capture(),
    mutationFn: ({ key, payload }: { key: string; payload: LifecycleProviderUpdatePayload }) =>
      updateLifecycleProvider(key, payload, undefined, scope),
    onSuccess: async (updatedProvider, _variables, isCurrent) => {
      if (!isCurrent?.()) return;
      queryClient.setQueryData<LifecycleProviderConfig[]>(['lifecycle-providers', scopeKey], (current) =>
        current?.map((provider) =>
          provider.provider_key === updatedProvider.provider_key ? updatedProvider : provider,
        ) ?? current,
      );
      await invalidate();
      showToast('Lifecycle provider saved', 'success');
    },
    onError: (error: unknown) => showToast(getApiErrorMessage(error, 'Provider configuration update failed.'), 'error'),
  });

  const testMutation = useMutation({
    onMutate: () => mutationScope.capture(),
    mutationFn: (key: string) => testLifecycleProvider(key, undefined, scope),
    onSuccess: async (result, key, isCurrent) => {
      if (!isCurrent?.()) return;
      setTestResult((prev) => ({ ...prev, [key]: result }));
      await invalidate(persistsHealth(key));
      showToast(normalizeNotificationMessage(result.message, result.success ? 'Provider connection succeeded.' : 'Provider connection failed.'), result.success ? 'success' : 'error');
    },
    onError: (error: unknown) => showToast(getApiErrorMessage(error, 'Provider connection test failed.'), 'error'),
  });

  const syncMutation = useMutation({
    onMutate: () => mutationScope.capture(),
    mutationFn: (key: string) => syncLifecycleProvider(key, undefined, scope),
    onSuccess: async (result, key, isCurrent) => {
      if (!isCurrent?.()) return;
      // Current sync executes inline; an enqueue acknowledgment is not completion.
      await invalidate(['completed', 'failed'].includes(result.status) && persistsHealth(key));
      showToast(normalizeNotificationMessage(result.message, result.status === 'queued' ? 'Provider synchronization was queued successfully.' : ['completed', 'failed'].includes(result.status) ? 'Provider synchronization finished.' : 'Provider synchronization response received.'), result.status === 'failed' ? 'error' : 'success');
    },
    onError: (error: unknown) => showToast(getApiErrorMessage(error, 'Provider synchronization failed.'), 'error'),
  });

  const secretMutation = useMutation({
    onMutate: () => mutationScope.capture(),
    mutationFn: ({ key, name, value }: { key: string; name: string; value: string }) =>
      setLifecycleProviderSecret(key, { secret_name: name, secret_value: value }, undefined, scope),
    onSuccess: async (_result, _variables, isCurrent) => {
      if (!isCurrent?.()) return;
      await invalidate();
      showToast('Secret saved', 'success');
    },
    onError: (error: unknown) => showToast(getApiErrorMessage(error, 'Provider secret could not be saved.'), 'error'),
  });

  const deleteSecretMutation = useMutation({
    onMutate: () => mutationScope.capture(),
    mutationFn: ({ key, name }: { key: string; name: string }) => deleteLifecycleProviderSecret(key, name, undefined, scope),
    onSuccess: async (_result, _variables, isCurrent) => {
      if (!isCurrent?.()) return;
      await invalidate();
      showToast('Secret deleted', 'success');
    },
    onError: (error: unknown) => showToast(getApiErrorMessage(error, 'Provider secret could not be deleted.'), 'error'),
  });

  const reset = useMutation({ mutationFn: resetLifecycleProviderOverride, onMutate: () => mutationScope.capture(), onSuccess: async (_result, _key, isCurrent) => { if (isCurrent?.()) await invalidate(); } });
  const providers = providersQuery.data ?? [];
  const editedProvider = providers.find(provider => provider.provider_key === editing?.provider_key);

  return (
    <div className="space-y-5">
      <div className="overflow-hidden rounded-lg border border-border bg-surface">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-border bg-surface-muted text-xs uppercase tracking-wide text-hcl-muted">
            <tr>
              <th className="px-4 py-3">Provider</th>
              <th className="px-4 py-3">Type</th>
              <th className="px-4 py-3">Enabled</th>
              <th className="px-4 py-3">Priority</th>
              <th className="px-4 py-3">Health</th>
              <th className="px-4 py-3">Last Success</th>
              <th className="px-4 py-3">Last Failure</th>
              <th className="px-4 py-3">Secret</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {providersQuery.isLoading ? (
              <tr>
                <td className="px-4 py-5 text-hcl-muted" colSpan={9}>Loading providers</td>
              </tr>
            ) : providers.length === 0 ? (
              <tr>
                <td className="px-4 py-5 text-hcl-muted" colSpan={9}>No lifecycle providers configured</td>
              </tr>
            ) : (
              providers.map((provider) => (
                <tr key={provider.provider_key} className="align-middle">
                  <td className="px-4 py-3">
                    <div className="font-medium text-hcl-navy">{provider.display_name}</div>
                    <div className="text-xs text-hcl-muted">{provider.provider_key}</div>
                    <p className="text-xs">{provider.override_enabled ? `Tenant override · ${tenantName}` : 'Platform default'}</p>
                  </td>
                  <td className="px-4 py-3 text-hcl-muted">{provider.provider_type}</td>
                  <td className="px-4 py-3">
                    <input
                      type="checkbox"
                      checked={provider.enabled}
                      disabled={!canUpdate || (scope === 'tenant' && !provider.override_enabled)}
                      onChange={(e) =>
                        updateMutation.mutate({
                          key: provider.provider_key,
                          payload: { enabled: e.target.checked },
                        })
                      }
                      aria-label={`Toggle ${provider.display_name}`}
                    />
                  </td>
                  <td className="px-4 py-3 font-mono text-xs">{provider.priority}</td>
                  <td className="px-4 py-3"><ProviderHealthBadge status={provider.health_status} /></td>
                  <td className="px-4 py-3 text-xs text-hcl-muted">{formatDate(provider.last_success_at)}</td>
                  <td className="px-4 py-3 text-xs text-hcl-muted">
                    <span title={provider.last_failure_message ?? undefined}>{formatDate(provider.last_failure_at)}</span>
                  </td>
                  <td className="px-4 py-3">
                    {provider.has_secret ? <Badge variant="success">{scope === 'tenant' && !provider.override_enabled ? 'Credential managed by platform' : 'Credential configured ✓'}</Badge> : <Badge variant="gray">None</Badge>}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex justify-end gap-2">
                      {canUpdate && <Button variant="ghost" size="sm" onClick={() => setEditing(scope === 'tenant' && !provider.override_enabled ? { ...provider, has_secret: false, secret_preview: null } : provider)}>
                        <Settings className="h-3.5 w-3.5" />
                        {scope === 'tenant' && !provider.override_enabled ? `Override for ${tenantName}` : 'Edit'}
                      </Button>}
                      {scope === 'tenant' && provider.override_enabled && canUpdate && <Button variant="ghost" size="sm" loading={reset.isPending} onClick={() => reset.mutate(provider.provider_key)}>Reset to Platform Default</Button>}
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={!canTest}
                        loading={testMutation.isPending && testMutation.variables === provider.provider_key}
                        permission={`${scope}:lifecycle-provider:test`} onClick={() => testMutation.mutate(provider.provider_key)}
                      >
                        <TestTube2 className="h-3.5 w-3.5" />
                        Test
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={!canSync}
                        loading={syncMutation.isPending && syncMutation.variables === provider.provider_key}
                        permission={`${scope}:lifecycle-provider:sync`} onClick={() => syncMutation.mutate(provider.provider_key)}
                      >
                        <RefreshCw className="h-3.5 w-3.5" />
                        Sync
                      </Button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {Object.entries(testResult).length > 0 && (
        <div className="rounded-lg border border-border bg-surface p-4">
          <h2 className="text-sm font-semibold text-hcl-navy">Provider Health</h2>
          <div className="mt-3 grid gap-3 md:grid-cols-2">
            {Object.entries(testResult).map(([key, result]) => (
              <div key={key} className="rounded-md border border-border p-3">
                <div className="flex items-center justify-between">
                  <span className="font-medium text-hcl-navy">{key}</span>
                  <ProviderHealthBadge status={result.status} />
                </div>
                <p className="mt-2 text-sm text-hcl-muted">{result.message}</p>
                <p className="mt-1 text-xs text-hcl-muted">{result.latency_ms} ms · {formatDate(result.checked_at)}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {reset.error && <p role="alert">Unable to reset this override. Please retry.</p>}
      {editing && canUpdate && (
        <LifecycleProviderForm
          provider={editing}
          credentialConfigured={editedProvider ? (scope === 'tenant' && !editedProvider.override_enabled ? false : editedProvider.has_secret) : editing.has_secret}
          onClose={() => setEditing(null)}
          saving={updateMutation.isPending}
          onSave={async (key, payload) => {
            const isCurrent = mutationScope.capture();
            try {
              await updateMutation.mutateAsync({ key, payload });
              if (isCurrent()) setEditing(null);
            } catch { /* onError displays the failure; keep the draft open. */ }
          }}
          onSaveSecret={async (key, name, value) => {
            try { await secretMutation.mutateAsync({ key, name, value }); } catch { /* Preserve the draft; onError reports the failure. */ }
          }}
          onDeleteSecret={async (key, name) => {
            try { await deleteSecretMutation.mutateAsync({ key, name }); } catch { /* onError reports the failure. */ }
          }}
        />
      )}
    </div>
  );
}
