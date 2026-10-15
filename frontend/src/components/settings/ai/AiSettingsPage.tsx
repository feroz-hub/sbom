'use client';

import styles from './ai-configuration.module.css';

import { useRef, useState } from 'react';
import { Plus } from 'lucide-react';
import {
  useAiCredentials,
  useAiCredentialSettings,
} from '@/hooks/useAiCredentials';
import type { AiCredential } from '@/types/ai';
import type { EffectiveAiConfiguration } from '@/lib/api';
import { AddProviderDialog } from './AddProviderDialog';
import { BudgetCapsForm } from './BudgetCapsForm';
import { EditProviderDialog } from './EditProviderDialog';
import { ProvidersList } from './ProvidersList';
import { UsageSummary } from './UsageSummary';
import { useAiConfigurationScope } from './ConfigurationScope';
import { ConfigurationSummary } from './ConfigurationSummary';
import { ProviderModels } from './ProvidersList/ProviderModels';

const tabs = ['Providers', 'Models', 'Defaults & Overrides'] as const;
type Tab = (typeof tabs)[number];

export function AiSettingsPage({
  effective,
}: {
  effective?: EffectiveAiConfiguration;
}) {
  const { scope, canUpdate = true } = useAiConfigurationScope();
  const {
    data: settings,
    error: settingsError,
    refetch: retrySettings,
  } = useAiCredentialSettings();
  const { data: credentials, isLoading, isError, refetch } = useAiCredentials();
  const [tab, setTab] = useState<Tab>('Providers');
  const [providerFilter, setProviderFilter] = useState('');
  const [search, setSearch] = useState('');
  const [showAdd, setShowAdd] = useState(false);
  const [editing, setEditing] = useState<AiCredential | null>(null);
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);
  const [notice, setNotice] = useState('');
  const manageModels = (credential: AiCredential) => {
    setProviderFilter(String(credential.id));
    setSearch('');
    setTab('Models');
    tabRefs.current[1]?.focus();
  };
  const saved = () => setNotice('Provider configuration saved.');

  return (
    <section
      className={`${styles.page} min-w-0 space-y-6 text-sm`}
      aria-label="AI Configuration"
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-semibold text-hcl-navy">
            Providers and models
          </h2>
          <p className="mt-1 text-hcl-muted">
            Manage connections and choose an active model for each provider.
          </p>
        </div>
        {canUpdate && (
          <button
            type="button"
            onClick={() => setShowAdd(true)}
            className="inline-flex min-h-10 items-center gap-2 rounded-lg bg-primary px-4 font-medium text-white"
          >
            <Plus className="h-4 w-4" aria-hidden />
            Add provider
          </button>
        )}
      </div>
      {notice && (
        <p
          role="status"
          className="rounded-lg border border-border bg-surface p-3 text-hcl-navy"
        >
          {notice}
        </p>
      )}
      {!canUpdate && (
        <p className="text-hcl-muted">
          Read-only access. Updating providers, models and defaults requires
          configuration update permission.
        </p>
      )}
      {settingsError && (
        <p
          role="alert"
          className="rounded-lg border border-border p-3 text-red-700 dark:text-red-300"
        >
          Unable to load budget controls.{' '}
          <button
            type="button"
            onClick={() => retrySettings()}
            className="underline"
          >
            Retry settings
          </button>
        </p>
      )}
      {settings?.kill_switch_active && (
        <div
          role="alert"
          className="rounded-lg border border-red-300 bg-red-50 p-3 text-red-800 dark:border-red-800 dark:bg-red-950 dark:text-red-200"
        >
          <strong>AI features are disabled by kill switch.</strong>{' '}
          {canUpdate && (
            <button
              type="button"
              className="underline"
              onClick={() => setTab('Defaults & Overrides')}
            >
              Review budget caps and controls
            </button>
          )}
        </div>
      )}
      <ConfigurationSummary
        effective={effective}
        onDetails={() => {
          setTab('Defaults & Overrides');
          tabRefs.current[2]?.focus();
        }}
      />
      <div
        role="tablist"
        aria-label="AI configuration views"
        className="flex flex-wrap gap-1 border-b border-border"
      >
        {tabs.map((name, index) => (
          <button
            key={name}
            ref={(el) => {
              tabRefs.current[index] = el;
            }}
            type="button"
            role="tab"
            id={`ai-tab-${index}`}
            aria-controls={`ai-panel-${index}`}
            aria-selected={tab === name}
            tabIndex={tab === name ? 0 : -1}
            onClick={() => setTab(name)}
            onKeyDown={(event) => {
              const next =
                event.key === 'ArrowRight'
                  ? (index + 1) % tabs.length
                  : event.key === 'ArrowLeft'
                    ? (index + tabs.length - 1) % tabs.length
                    : event.key === 'Home'
                      ? 0
                      : event.key === 'End'
                        ? tabs.length - 1
                        : null;
              if (next !== null) {
                event.preventDefault();
                setTab(tabs[next]);
                tabRefs.current[next]?.focus();
              }
            }}
            className={`min-h-11 rounded-t-lg border-b-2 px-4 font-medium focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary ${tab === name ? 'border-primary text-link' : 'border-transparent text-hcl-muted hover:bg-surface-muted'}`}
          >
            {name}
          </button>
        ))}
      </div>
      <div
        role="tabpanel"
        id={`ai-panel-${tabs.indexOf(tab)}`}
        aria-labelledby={`ai-tab-${tabs.indexOf(tab)}`}
        tabIndex={0}
        className="min-w-0 focus-visible:outline-primary"
      >
        {tab === 'Providers' && (
          <ProvidersList
            onAdd={() => setShowAdd(true)}
            onEdit={setEditing}
            onManageModels={manageModels}
          />
        )}
        {tab === 'Models' && (
          <section aria-label="Models" className="space-y-4">
            <div className="flex flex-wrap gap-4">
              <label className="flex min-w-0 flex-col gap-1 text-hcl-muted">
                Provider
                <select
                  value={providerFilter}
                  onChange={(e) => setProviderFilter(e.target.value)}
                  className="min-h-10 max-w-full rounded-lg border border-border bg-surface px-3 text-hcl-navy"
                >
                  <option value="">All providers</option>
                  {credentials?.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.provider_name} · {c.label}
                    </option>
                  ))}
                </select>
              </label>
              <label className="flex min-w-0 flex-1 flex-col gap-1 text-hcl-muted">
                Search models
                <input
                  type="search"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Model name or provider ID"
                  className="min-h-10 w-full rounded-lg border border-border bg-surface px-3 text-hcl-navy"
                />
              </label>
            </div>
            {isLoading && <p role="status">Loading providers…</p>}
            {isError && (
              <p role="alert">
                Unable to load providers.{' '}
                <button
                  type="button"
                  className="underline"
                  onClick={() => refetch()}
                >
                  Retry
                </button>
              </p>
            )}
            {credentials?.length === 0 && (
              <p className="rounded-xl border border-dashed border-border p-6 text-hcl-muted">
                Add a provider to discover models.
              </p>
            )}
            {credentials
              ?.filter(
                (c) => !providerFilter || String(c.id) === providerFilter,
              )
              .map((c) => (
                <ProviderModels
                  key={c.id}
                  credentialId={c.id}
                  providerName={`${c.provider_name} · ${c.label}`}
                  enabled={c.enabled}
                  search={search}
                />
              ))}
          </section>
        )}
        {tab === 'Defaults & Overrides' && (
          <div className="space-y-6">
            <section className="rounded-xl border border-border bg-surface p-5">
              <h2 className="text-base font-semibold text-hcl-navy">
                Defaults and inheritance
              </h2>
              <p className="mt-2 text-hcl-muted">
                Platform default → Tenant override (when present) → Effective
                tenant configuration
              </p>
              <p className="mt-3 text-hcl-muted">
                Each provider has its own active model. The default provider is
                selected separately. Platform changes apply only to tenants
                without an override.
              </p>
              {effective && (
                <dl className="mt-4 space-y-3 border-t border-border-subtle pt-4">
                  {effective.configured_providers.map((provider, index) => (
                    <div key={provider.selection_key ?? index}>
                      <dt className="font-medium text-hcl-navy">
                        {provider.provider_name} ·{' '}
                        {provider.enabled ? 'Enabled' : 'Disabled'}
                      </dt>
                      <dd className="mt-1 break-all font-mono text-sm text-hcl-navy">
                        {provider.model || 'No model configured'}
                      </dd>
                      <dd className="mt-1 text-hcl-muted">
                        Credentials:{' '}
                        {provider.credential_present
                          ? 'Configured'
                          : 'Not configured (may not be required)'}
                      </dd>
                    </div>
                  ))}
                </dl>
              )}
              {canUpdate && (
                <button
                  type="button"
                  onClick={() => {
                    setTab('Providers');
                    tabRefs.current[0]?.focus();
                  }}
                  className="mt-4 min-h-10 rounded-lg border border-border px-3 text-hcl-navy"
                >
                  Manage provider defaults
                </button>
              )}
            </section>
            {canUpdate && <BudgetCapsForm />}
            {!canUpdate && settings && (
              <section
                className="rounded-xl border border-border bg-surface p-5 text-hcl-navy"
                aria-label="Budget controls"
              >
                <h2 className="font-semibold">Budget caps</h2>
                <p className="mt-2">
                  Per request: ${settings.budget_per_request_usd} · Per scan: $
                  {settings.budget_per_scan_usd} · Daily: $
                  {settings.budget_daily_usd}
                </p>
                <p className="mt-2">
                  AI features:{' '}
                  {settings.feature_enabled ? 'Enabled' : 'Disabled'} · Kill
                  switch: {settings.kill_switch_active ? 'Active' : 'Inactive'}
                </p>
              </section>
            )}
            {scope === 'tenant' && <UsageSummary />}
          </div>
        )}
      </div>
      {canUpdate && (
        <>
          <AddProviderDialog
            open={showAdd}
            onClose={() => setShowAdd(false)}
            onSaved={saved}
          />
          <EditProviderDialog
            credential={editing}
            onClose={() => setEditing(null)}
            onSaved={saved}
          />
        </>
      )}
    </section>
  );
}
