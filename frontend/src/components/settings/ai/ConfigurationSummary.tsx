'use client';

import type { EffectiveAiConfiguration } from '@/lib/api';
import { useAiCredentials, useProviderCatalog } from '@/hooks/useAiCredentials';
import { useAiConfigurationScope } from './ConfigurationScope';

export function ConfigurationSummary({
  effective,
  onDetails,
}: {
  effective?: EffectiveAiConfiguration;
  onDetails: () => void;
}) {
  const { scope } = useAiConfigurationScope();
  const { data: credentials } = useAiCredentials();
  const { data: catalog } = useProviderCatalog();
  // The effective diagnostic includes environment-backed providers as well as saved rows.
  const provider = effective?.configured_providers.find((p) =>
    effective.default_selection_key
      ? p.selection_key === effective.default_selection_key
      : p.is_default,
  );
  const saved = credentials?.find((c) => c.is_default && c.enabled);
  const name =
    provider?.provider_name ?? (!effective ? saved?.provider_name : undefined);
  const label = catalog?.find((p) => p.name === name)?.display_name ?? name;
  const model =
    provider?.model ?? (!effective ? saved?.default_model : undefined);
  return (
    <section
      aria-label="Effective configuration"
      className="rounded-xl border border-border bg-surface p-5 shadow-card sm:p-6"
    >
      <p className="text-xs font-semibold uppercase tracking-wider text-hcl-muted">
        Effective {scope} configuration
      </p>
      <dl className="mt-4 grid gap-4 lg:grid-cols-3">
        <div>
          <dt className="text-sm text-hcl-muted">Default provider</dt>
          <dd className="mt-1 font-semibold text-hcl-navy">
            {label ?? 'No default selected'}
          </dd>
        </div>
        <div className="min-w-0">
          <dt className="text-sm text-hcl-muted">
            Active model of default provider
          </dt>
          <dd className="mt-1 break-all font-mono text-sm text-hcl-navy">
            {model || 'No model configured'}
          </dd>
        </div>
        <div>
          <dt className="text-sm text-hcl-muted">Configuration source</dt>
          <dd className="mt-1 font-medium text-hcl-navy">
            {effective?.source === 'TENANT_OVERRIDE'
              ? 'Tenant override'
              : scope === 'platform'
                ? 'Platform default'
                : 'Tenant configuration'}
          </dd>
        </div>
      </dl>
      <div className="mt-5 flex flex-wrap items-center justify-between gap-3 border-t border-border-subtle pt-4 text-sm">
        <p className="text-hcl-muted">
          Platform defaults apply to tenants that do not define their own AI
          configuration.
        </p>
        <button
          type="button"
          onClick={onDetails}
          className="min-h-10 rounded-lg px-2 font-medium text-link focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary"
        >
          View configuration details →
        </button>
      </div>
    </section>
  );
}
