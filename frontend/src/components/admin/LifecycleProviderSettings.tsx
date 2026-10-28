'use client';

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ChevronRight, GitBranch, Search, SearchX } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { LifecycleProviderDetails, ProviderStatus, recorded } from './LifecycleProviderDetails';
import { lastVerified, providerFilters, providerSubtitle, selectProviders, summarizeProviders, type ProviderFilter, type ProviderSort } from '@/lib/lifecycle-provider-presentation';
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
import type { LifecycleProviderConfig, LifecycleProviderTestResult, LifecycleProviderUpdatePayload } from '@/types';

export function LifecycleProviderSettings({ scope = 'tenant', scopeKey = 'tenant', tenantName = 'this tenant', canUpdate = true, canTest = true, canSync = true }: { scope?: ConfigurationScope; scopeKey?: string; tenantName?: string; canUpdate?: boolean; canTest?: boolean; canSync?: boolean }) {
  const queryClient = useQueryClient();
  const { showToast } = useToast();
  const mutationScope = useMutationScope();
  const [selected, setSelected] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<ProviderFilter>('All');
  const [sort, setSort] = useState<ProviderSort>('priority');
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
      setTestResult(prev => { const next = { ...prev }; delete next[updatedProvider.provider_key]; return next; });
      testMutation.reset();
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
      setTestResult(prev => { const next = { ...prev }; delete next[_variables.key]; return next; });
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
      setTestResult(prev => { const next = { ...prev }; delete next[_variables.key]; return next; });
      await invalidate();
      showToast('Secret deleted', 'success');
    },
    onError: (error: unknown) => showToast(getApiErrorMessage(error, 'Provider secret could not be deleted.'), 'error'),
  });

  const reset = useMutation({ mutationFn: resetLifecycleProviderOverride, onMutate: () => mutationScope.capture(), onSuccess: async (_result, _key, isCurrent) => { if (isCurrent?.()) { setTestResult(prev => { const next = { ...prev }; delete next[_key]; return next; }); await invalidate(); } } });
  const providers = providersQuery.data ?? [];
  const summary = summarizeProviders(providers);
  const visible = selectProviders(providers, search, filter, sort);
  const activeProvider = providers.find(provider => provider.provider_key === selected);
  return (
    <div className="space-y-5">
      <section aria-label="Provider summary" className="grid grid-cols-2 overflow-hidden rounded-xl border border-border bg-surface md:grid-cols-4">
        {([{ label: 'Total providers', value: summary.total, hint: 'Available intelligence sources' }, { label: 'Verified operational', value: summary.verified, hint: 'Enabled with stored verification' }, { label: 'Needs attention', value: summary.attention, hint: 'Enabled sources requiring review' }, { label: 'Disabled providers', value: summary.disabled, hint: 'Excluded from runtime use' }]).map(metric => <div key={metric.label} className="border-b border-r border-border px-5 py-4 last:border-r-0 md:border-b-0"><p className="text-xs font-medium text-hcl-muted">{metric.label}</p><p className="mt-1 text-2xl font-semibold tabular-nums text-hcl-navy">{providersQuery.isLoading ? '…' : providersQuery.isError && !providersQuery.data ? 'Unavailable' : metric.value}</p><p className="mt-1 text-[11px] text-hcl-muted">{metric.hint}</p></div>)}
      </section>
      <section className="overflow-hidden rounded-xl border border-border bg-surface" aria-label="Provider directory">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-5 py-4"><div><h2 className="text-sm font-semibold text-hcl-navy">Provider directory</h2><p className="mt-1 text-xs text-hcl-muted">Review sources, then manage configuration and verification.</p></div><span className="text-xs text-hcl-muted">{summary.unsupported > 0 ? `${summary.unsupported} unsupported` : 'Capability-aware configuration'}</span></div>
        <div className="space-y-3 border-b border-border p-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between"><label className="relative block w-full sm:max-w-sm"><span className="sr-only">Search providers</span><Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-hcl-muted" aria-hidden="true" /><input value={search} onChange={event => setSearch(event.target.value)} placeholder="Search providers" className="h-9 w-full rounded-lg border border-border bg-background pl-9 pr-3 text-sm outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue" /></label><label className="flex shrink-0 items-center gap-2 text-xs text-hcl-muted">Sort by<select aria-label="Sort providers" value={sort} onChange={event => setSort(event.target.value as ProviderSort)} className="h-9 rounded-lg border border-border bg-background px-2 text-sm text-hcl-navy outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue"><option value="priority">Priority</option><option value="name">Name</option><option value="status">Verification status</option><option value="verified">Last verified</option></select></label></div>
          <div className="flex flex-wrap gap-1.5" aria-label="Filter providers">{providerFilters.map(item => <button type="button" key={item} aria-pressed={filter === item} onClick={() => setFilter(item)} className={`rounded-md px-3 py-1.5 text-xs font-medium outline-none transition-colors focus-visible:ring-2 focus-visible:ring-hcl-blue motion-reduce:transition-none ${filter === item ? 'bg-hcl-light text-hcl-blue' : 'text-hcl-muted hover:bg-surface-muted hover:text-hcl-navy'}`}>{item}</button>)}</div>
        </div>
        {providersQuery.isError ? <div role="alert" className="space-y-3 p-8 text-center"><p className="font-medium text-hcl-navy">Unable to load provider configuration</p><p className="text-sm text-hcl-muted">Your saved settings have not been changed. Retry when the service is available.</p><Button variant="secondary" size="sm" onClick={() => void providersQuery.refetch()} loading={providersQuery.isFetching}>Retry</Button></div> : providersQuery.isLoading ? <div role="status" className="p-10 text-center text-sm text-hcl-muted">Loading provider configuration…</div> : visible.length === 0 ? <div className="space-y-3 p-10 text-center"><SearchX className="mx-auto h-6 w-6 text-hcl-muted" /><p className="text-sm font-medium text-hcl-navy">{providers.length ? 'No providers match your search' : 'No lifecycle providers configured'}</p><p className="text-xs text-hcl-muted">{providers.length ? 'Try a different name or clear the filters.' : 'Provider configuration will appear here when available from the service.'}</p>{providers.length > 0 && <Button variant="secondary" size="sm" onClick={() => { setSearch(''); setFilter('All'); }}>Clear filters</Button>}</div> : <>
          <table className="w-full table-fixed text-left text-sm"><caption className="sr-only">Lifecycle provider directory</caption><thead className="border-b border-border bg-surface-muted text-[11px] uppercase tracking-wide text-hcl-muted"><tr><th scope="col" className="px-4 py-3 sm:w-[32%]">Provider</th><th scope="col" className="hidden w-[12%] px-3 py-3 xl:table-cell">Source type</th><th scope="col" className="hidden w-[11%] px-3 py-3 md:table-cell">Runtime</th><th scope="col" className="hidden w-[19%] px-3 py-3 md:table-cell">Verification</th><th scope="col" className="hidden w-[15%] px-3 py-3 lg:table-cell">Last verified</th><th scope="col" className="w-24 px-4 py-3 text-right">Actions</th></tr></thead><tbody className="divide-y divide-border">{visible.map(provider => <tr key={provider.provider_key} className="transition-colors hover:bg-surface-muted/50 motion-reduce:transition-none"><td className="min-w-0 px-4 py-4"><button type="button" onClick={() => setSelected(provider.provider_key)} className="block max-w-full truncate text-left font-medium text-hcl-navy outline-none hover:text-hcl-blue focus-visible:rounded focus-visible:ring-2 focus-visible:ring-hcl-blue" title={provider.display_name}>{provider.display_name}</button><p title={providerSubtitle(provider)} className="mt-1 truncate text-xs text-hcl-muted">{providerSubtitle(provider)}</p>{scope === 'tenant' && provider.override_enabled && <span className="mt-1 inline-flex items-center gap-1 text-[10px] text-hcl-muted"><GitBranch className="h-3 w-3" aria-hidden="true" />Tenant override</span>}<div className="mt-2 flex flex-wrap items-center gap-2 md:hidden"><span className="text-xs text-hcl-muted">{provider.enabled ? 'Enabled' : 'Disabled'}</span><ProviderStatus provider={provider} /></div></td><td className="hidden truncate px-3 py-4 text-xs text-hcl-muted xl:table-cell" title={provider.capabilities?.data_source_type}>{provider.capabilities?.data_source_type ?? provider.provider_type}</td><td className="hidden px-3 py-4 md:table-cell"><span className="inline-flex items-center gap-1.5 text-xs text-hcl-muted"><span aria-hidden="true" className={`h-1.5 w-1.5 rounded-full ${provider.enabled ? 'bg-hcl-blue' : 'bg-slate-400'}`} />{provider.enabled ? 'Enabled' : 'Disabled'}</span></td><td className="hidden px-3 py-4 md:table-cell"><ProviderStatus provider={provider} /></td><td className="hidden px-3 py-4 text-xs text-hcl-muted lg:table-cell">{recorded(lastVerified(provider))}</td><td className="px-4 py-4 text-right"><Button variant="ghost" size="sm" aria-label={`Manage ${provider.display_name}`} onClick={() => setSelected(provider.provider_key)}>Manage<ChevronRight className="h-3.5 w-3.5" aria-hidden="true" /></Button></td></tr>)}</tbody></table><div role="status" className="border-t border-border px-4 py-3 text-xs text-hcl-muted">Showing {visible.length} of {providers.length} providers</div>
        </>}
      </section>
      <details className="rounded-lg border border-border bg-surface px-4 py-3 text-xs leading-relaxed text-hcl-muted"><summary className="cursor-pointer font-medium text-hcl-navy">How to interpret verification</summary><p className="mt-3">Verified operational counts enabled providers with stored successful network or local database verification, excluding static references and unsupported integrations. A saved configuration or HTTP response alone is not sufficient. Providers needing attention are enabled sources with missing configuration, no successful verification, or a recorded failure. A successful sample check does not establish lifecycle coverage for every component.</p></details>
      {activeProvider && <LifecycleProviderDetails key={activeProvider.provider_key} provider={activeProvider} result={testResult[activeProvider.provider_key]} verificationError={testMutation.isError && testMutation.variables === activeProvider.provider_key ? getApiErrorMessage(testMutation.error, 'Verification request failed.') : null} scope={scope} tenantName={tenantName} canUpdate={canUpdate} canTest={canTest} canSync={canSync} saving={updateMutation.isPending || secretMutation.isPending || deleteSecretMutation.isPending} verifying={testMutation.isPending} reloading={syncMutation.isPending} resetting={reset.isPending} onClose={() => setSelected(null)} onVerify={() => testMutation.mutate(activeProvider.provider_key)} onReload={() => syncMutation.mutate(activeProvider.provider_key)} onReset={() => reset.mutateAsync(activeProvider.provider_key)} onSave={async (key, payload) => { await updateMutation.mutateAsync({ key, payload }); }} onSaveSecret={async (key, name, value) => { await secretMutation.mutateAsync({ key, name, value }); }} onDeleteSecret={async (key, name) => { await deleteSecretMutation.mutateAsync({ key, name }); }} />}
    </div>
  );
}
