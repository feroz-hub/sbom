import type { LifecycleProviderCapabilities, LifecycleProviderConfig, LifecycleProviderTestResult } from '@/types';

export const successfulProbe: LifecycleProviderTestResult = {
  success: true, status: 'healthy', checked_at: '2026-10-16T00:00:00Z', latency_ms: 240,
  provider_key: 'endoflife_date', probe_type: 'network', configuration_valid: true, connection_verified: true,
  authentication_verified: null, response_valid: true, sample_matched: true, lifecycle_evidence_found: true,
  real_provider_call: true, http_status: 200, sample_component: { name: 'debian', version: '12' },
  message: 'Provider response verified; lifecycle coverage is reported separately.',
};
export function makeProvider(overrides: Partial<LifecycleProviderConfig> = {}, capabilities: Partial<LifecycleProviderCapabilities> = {}): LifecycleProviderConfig {
  return {
    provider_key: 'endoflife_date', display_name: 'endoflife.date', provider_type: 'endoflife_date', enabled: true,
    priority: 30, base_url: 'https://endoflife.date/api', feed_urls: [], config: {}, timeout_seconds: 5, max_retries: 0,
    circuit_breaker_enabled: true, cache_ttl: { known_days: null, unknown_hours: null, failure_minutes: null, deprecated_days: null },
    health_status: 'unknown', last_success_at: null, last_failure_at: null, last_failure_message: null, has_secret: false,
    secret_preview: null, updated_at: '2026-10-16T00:00:00Z', source: 'TENANT_OVERRIDE', override_enabled: true,
    configuration_status: 'configured', ...overrides,
    capabilities: { data_source_type: 'API', effective_endpoint: 'https://endoflife.date/api', coverage: 'Mapped product release cycles',
      implemented: true, editable_endpoint: true, feed_urls: false, config_fields: [], secret_name: null, sync_action: null,
      network: true, circuit_state_scope: 'process-local', cache_defaults: { known_days: 14, unknown_hours: 24, failure_minutes: 30, deprecated_days: 7 }, ...capabilities },
  };
}
// Explicit synthetic API fixtures for tests/visual QA, never imported by production UI.
export const visualProviders: LifecycleProviderConfig[] = [
  makeProvider({ provider_key: 'redhat_lifecycle', display_name: 'Red Hat Lifecycle', priority: 10, base_url: null }, { data_source_type: 'Static Reference', network: false, editable_endpoint: false, effective_endpoint: 'https://access.redhat.com/support/policy/updates/errata', coverage: 'RHEL 7–9 only; embedded reference, freshness unverified' }),
  makeProvider({ provider_key: 'official_vendor_lifecycle', display_name: 'Official Vendor Lifecycle', priority: 10, base_url: null, configuration_status: 'unsupported' }, { implemented: false, network: false, editable_endpoint: false, data_source_type: 'Unsupported', effective_endpoint: null, coverage: 'Placeholder: no live vendor integration implemented' }),
  makeProvider({ last_probe: successfulProbe, health_status: 'healthy' }),
  makeProvider({ provider_key: 'package_registry', display_name: 'Package Registry', priority: 50, base_url: null, last_probe: { ...successfulProbe, lifecycle_evidence_found: false }, health_status: 'healthy' }, { editable_endpoint: false, data_source_type: 'Registry', effective_endpoint: 'npm / PyPI / NuGet / Maven Central / RubyGems', coverage: 'Registry deprecation and release metadata' }),
  makeProvider({ provider_key: 'deps_dev', display_name: 'deps.dev', priority: 60, base_url: null }, { editable_endpoint: false, effective_endpoint: 'https://api.deps.dev/v3', coverage: 'npm, PyPI, Maven, Go, NuGet, Cargo metadata' }),
  makeProvider({ provider_key: 'osv', display_name: 'OSV', priority: 70, base_url: null, last_probe: { ...successfulProbe, lifecycle_evidence_found: false }, health_status: 'healthy' }, { editable_endpoint: false, effective_endpoint: 'https://api.osv.dev/v1/query', coverage: 'Vulnerability advisories only; does not establish lifecycle support' }),
  makeProvider({ provider_key: 'repository_health', display_name: 'Repository Health', priority: 80, base_url: null, health_status: 'degraded', last_probe: { ...successfulProbe, success: false, status: 'degraded', authentication_verified: false, response_valid: false, lifecycle_evidence_found: false, error_code: 'http_401', http_status: 401, message: 'Provider response unavailable, incomplete or invalid.' }, has_secret: true }, { editable_endpoint: false, secret_name: 'github_token', effective_endpoint: 'GitHub / GitLab / Bitbucket public APIs', coverage: 'Archive and activity signals; inactivity does not establish EOL' }),
  makeProvider({ provider_key: 'custom_vendor_records', display_name: 'Custom Vendor Records', priority: 5, enabled: false, base_url: null }, { editable_endpoint: false, network: false, data_source_type: 'Local DB', effective_endpoint: 'Lifecycle vendor records', coverage: 'Administrator-maintained records' }),
  makeProvider({ provider_key: 'openeox', display_name: 'OpenEoX', priority: 20, enabled: false, base_url: null, configuration_status: 'missing_source' }, { editable_endpoint: false, feed_urls: true, effective_endpoint: null, data_source_type: 'Custom Feed', coverage: 'Configured OpenEoX-compatible JSON feeds' }),
  makeProvider({ provider_key: 'xeol_api', display_name: 'Xeol API', priority: 40, enabled: false, base_url: 'https://edb-prod.xeol.io/eol/check' }, { secret_name: 'api_key', effective_endpoint: 'https://edb-prod.xeol.io/eol/check', coverage: 'Xeol component lookup; credentials may be required' }),
  makeProvider({ provider_key: 'xeol_db', display_name: 'Local Xeol DB', priority: 40, enabled: false, base_url: null, config: { db_path: null }, configuration_status: 'missing_source' }, { network: false, editable_endpoint: false, config_fields: ['db_path'], effective_endpoint: null, data_source_type: 'Local DB', sync_action: 'reload_cache', coverage: 'Readable Xeol SQLite or JSON export' }),
].map(p => ({ ...p, source: 'PLATFORM_DEFAULT', override_enabled: false }));
