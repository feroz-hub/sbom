import type { LifecycleProviderConfig, LifecycleProviderTestResult } from '@/types';

export type ProviderFilter = 'All' | 'Enabled' | 'Disabled' | 'Needs attention' | 'Verified' | 'Unsupported';
export const providerFilters: ProviderFilter[] = ['All', 'Enabled', 'Disabled', 'Needs attention', 'Verified', 'Unsupported'];
export type ProviderSort = 'priority' | 'name' | 'status' | 'verified';

export function hasVerificationProof(provider: LifecycleProviderConfig, result = provider.last_probe): boolean {
  if (!result?.success || result.status !== 'healthy' || !result.configuration_valid || !result.response_valid || !result.checked_at || !Number.isFinite(Date.parse(result.checked_at))) return false;
  return provider.capabilities?.network
    ? result.probe_type === 'network' && result.connection_verified === true && result.real_provider_call === true
    : result.probe_type === 'local_verification';
}

export function isStaticReference(provider: LifecycleProviderConfig) { return provider.capabilities?.data_source_type === 'Static Reference'; }
export function isUnsupported(provider: LifecycleProviderConfig) { return provider.capabilities?.implemented === false; }
export function needsAttention(provider: LifecycleProviderConfig) {
  return provider.enabled && !isUnsupported(provider) && (
    ['invalid', 'missing_source'].includes(provider.configuration_status ?? '') ||
    ['degraded', 'failed'].includes(provider.health_status) || !hasVerificationProof(provider)
  );
}
export function providerStatus(provider: LifecycleProviderConfig, result?: LifecycleProviderTestResult | null): { label: string; tone: 'gray' | 'success' | 'warning' | 'error'; help: string } {
  if (isUnsupported(provider)) return { label: 'Unsupported', tone: 'gray', help: 'Not implemented — no live vendor integration.' };
  if (['invalid', 'missing_source'].includes(provider.configuration_status ?? '')) return { label: 'Configuration needed', tone: 'warning', help: 'Complete the source settings before verification.' };
  const probe = result ?? provider.last_probe;
  if (probe && !probe.success && probe.status !== 'disabled') return { label: 'Failed', tone: 'error', help: 'The last verification did not succeed. Review the verification details.' };
  if (provider.health_status === 'degraded') return { label: 'Degraded', tone: 'warning', help: 'A provider failure was recorded. Verify it again to check the current state.' };
  if (hasVerificationProof(provider, probe)) return isStaticReference(provider)
    ? { label: 'Reference checked', tone: 'gray', help: 'Static RHEL reference — freshness not verified.' }
    : { label: 'Verified', tone: 'success', help: 'Successful verification is recorded. This does not establish coverage for every component.' };
  return { label: 'Not verified yet', tone: 'gray', help: 'No successful verification evidence is recorded for this configuration.' };
}
export function lastVerified(provider: LifecycleProviderConfig) { return hasVerificationProof(provider) ? provider.last_probe?.checked_at ?? null : null; }
export function summarizeProviders(providers: LifecycleProviderConfig[]) {
  return {
    total: providers.length,
    verified: providers.filter(p => p.enabled && !isUnsupported(p) && !isStaticReference(p) && providerStatus(p).label === 'Verified').length,
    attention: providers.filter(needsAttention).length,
    disabled: providers.filter(p => !p.enabled).length,
    unsupported: providers.filter(isUnsupported).length,
  };
}
export function selectProviders(providers: LifecycleProviderConfig[], search: string, filter: ProviderFilter, sort: ProviderSort) {
  const needle = search.trim().toLocaleLowerCase();
  return providers.filter(p => `${p.display_name} ${p.capabilities?.data_source_type ?? p.provider_type} ${p.capabilities?.coverage ?? ''}`.toLocaleLowerCase().includes(needle))
    .filter(p => filter === 'All' || (filter === 'Enabled' && p.enabled) || (filter === 'Disabled' && !p.enabled) || (filter === 'Needs attention' && needsAttention(p)) || (filter === 'Verified' && providerStatus(p).label === 'Verified') || (filter === 'Unsupported' && isUnsupported(p)))
    .sort((a, b) => (sort === 'name' ? a.display_name.localeCompare(b.display_name) : sort === 'status' ? providerStatus(a).label.localeCompare(providerStatus(b).label) : sort === 'verified' ? (Date.parse(lastVerified(b) ?? '') || 0) - (Date.parse(lastVerified(a) ?? '') || 0) : a.priority - b.priority) || a.display_name.localeCompare(b.display_name));
}
export function providerSubtitle(provider: LifecycleProviderConfig) {
  if (isUnsupported(provider)) return 'Not implemented — no live vendor integration.';
  if (isStaticReference(provider)) return 'Static RHEL reference — freshness not verified.';
  const descriptions: Record<string, string> = {
    endoflife_date: 'Product release and support timelines', deps_dev: 'Package metadata and advisory context',
    osv: 'Vulnerability advisory context', package_registry: 'Registry release and deprecation signals',
    repository_health: 'Repository maintenance signals', custom_vendor_records: 'Curated lifecycle records',
    openeox: 'Lifecycle intelligence from configured feeds', xeol_api: 'Component lifecycle intelligence', xeol_db: 'Lifecycle intelligence from a local database',
  };
  return descriptions[provider.provider_key] ?? provider.capabilities?.data_source_type ?? 'Lifecycle intelligence source';
}
