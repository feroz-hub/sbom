'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { RefreshCw, Settings, TestTube2 } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { ProviderHealthBadge } from './ProviderHealthBadge';
import { LifecycleProviderForm } from './LifecycleProviderForm';
import { useToast } from '@/hooks/useToast';
import { getApiErrorMessage, normalizeNotificationMessage } from '@/lib/notifications';
import {
  deleteLifecycleProviderSecret,
  listLifecycleProviders,
  setLifecycleProviderSecret,
  syncLifecycleProvider,
  testLifecycleProvider,
  updateLifecycleProvider,
} from '@/lib/api';
import { formatDate } from '@/lib/utils';
import type { LifecycleProviderConfig, LifecycleProviderTestResult, LifecycleProviderUpdatePayload } from '@/types';

export function LifecycleProviderSettings() {
  const queryClient = useQueryClient();
  const { showToast } = useToast();
  const [editing, setEditing] = useState<LifecycleProviderConfig | null>(null);
  const [testResult, setTestResult] = useState<Record<string, LifecycleProviderTestResult>>({});

  const providersQuery = useQuery({
    queryKey: ['lifecycle-providers'],
    queryFn: ({ signal }) => listLifecycleProviders(signal),
    staleTime: 30_000,
  });

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['lifecycle-providers'] });

  const updateMutation = useMutation({
    mutationFn: ({ key, payload }: { key: string; payload: LifecycleProviderUpdatePayload }) =>
      updateLifecycleProvider(key, payload),
    onSuccess: (updatedProvider) => {
      queryClient.setQueryData<LifecycleProviderConfig[]>(['lifecycle-providers'], (current) =>
        current?.map((provider) =>
          provider.provider_key === updatedProvider.provider_key ? updatedProvider : provider,
        ) ?? current,
      );
      invalidate();
      showToast('Lifecycle provider saved', 'success');
    },
    onError: (error: unknown) => showToast(getApiErrorMessage(error, 'Provider configuration update failed.'), 'error'),
  });

  const testMutation = useMutation({
    mutationFn: (key: string) => testLifecycleProvider(key),
    onSuccess: (result, key) => {
      setTestResult((prev) => ({ ...prev, [key]: result }));
      void invalidate();
      showToast(normalizeNotificationMessage(result.message, result.success ? 'Provider connection succeeded.' : 'Provider connection failed.'), result.success ? 'success' : 'error');
    },
    onError: (error: unknown) => showToast(getApiErrorMessage(error, 'Provider connection test failed.'), 'error'),
  });

  const syncMutation = useMutation({
    mutationFn: (key: string) => syncLifecycleProvider(key),
    onSuccess: (result) => {
      void invalidate();
      showToast(normalizeNotificationMessage(result.message, 'Provider synchronization was queued successfully.'), 'success');
    },
    onError: (error: unknown) => showToast(getApiErrorMessage(error, 'Provider synchronization failed.'), 'error'),
  });

  const secretMutation = useMutation({
    mutationFn: ({ key, name, value }: { key: string; name: string; value: string }) =>
      setLifecycleProviderSecret(key, { secret_name: name, secret_value: value }),
    onSuccess: () => {
      void invalidate();
      showToast('Secret saved', 'success');
    },
    onError: (error: unknown) => showToast(getApiErrorMessage(error, 'Provider secret could not be saved.'), 'error'),
  });

  const deleteSecretMutation = useMutation({
    mutationFn: ({ key, name }: { key: string; name: string }) => deleteLifecycleProviderSecret(key, name),
    onSuccess: () => {
      void invalidate();
      showToast('Secret deleted', 'success');
    },
    onError: (error: unknown) => showToast(getApiErrorMessage(error, 'Provider secret could not be deleted.'), 'error'),
  });

  const providers = providersQuery.data ?? [];

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
                  </td>
                  <td className="px-4 py-3 text-hcl-muted">{provider.provider_type}</td>
                  <td className="px-4 py-3">
                    <input
                      type="checkbox"
                      checked={provider.enabled}
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
                    {provider.has_secret ? <Badge variant="success">{provider.secret_preview}</Badge> : <Badge variant="gray">None</Badge>}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex justify-end gap-2">
                      <Button variant="ghost" size="sm" onClick={() => setEditing(provider)}>
                        <Settings className="h-3.5 w-3.5" />
                        Edit
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        loading={testMutation.isPending && testMutation.variables === provider.provider_key}
                        onClick={() => testMutation.mutate(provider.provider_key)}
                      >
                        <TestTube2 className="h-3.5 w-3.5" />
                        Test
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        loading={syncMutation.isPending && syncMutation.variables === provider.provider_key}
                        onClick={() => syncMutation.mutate(provider.provider_key)}
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

      {editing && (
        <LifecycleProviderForm
          provider={editing}
          onClose={() => setEditing(null)}
          saving={updateMutation.isPending}
          onSave={async (key, payload) => {
            await updateMutation.mutateAsync({ key, payload });
            setEditing(null);
          }}
          onSaveSecret={async (key, name, value) => {
            await secretMutation.mutateAsync({ key, name, value });
          }}
          onDeleteSecret={async (key, name) => {
            await deleteSecretMutation.mutateAsync({ key, name });
          }}
        />
      )}
    </div>
  );
}
