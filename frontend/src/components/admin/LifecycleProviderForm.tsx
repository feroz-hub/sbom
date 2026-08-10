'use client';

import { useEffect, useMemo, useState } from 'react';
import { KeyRound, Save, Trash2, X } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import type { LifecycleProviderConfig, LifecycleProviderUpdatePayload } from '@/types';

interface Props {
  provider: LifecycleProviderConfig;
  onClose: () => void;
  onSave: (providerKey: string, payload: LifecycleProviderUpdatePayload) => Promise<void>;
  onSaveSecret: (providerKey: string, secretName: string, secretValue: string) => Promise<void>;
  onDeleteSecret: (providerKey: string, secretName: string) => Promise<void>;
  saving?: boolean;
}

const providerSpecificSecretName = (provider: LifecycleProviderConfig) => {
  if (provider.provider_key === 'repository_health') return 'github_token';
  return 'api_key';
};

export function LifecycleProviderForm({
  provider,
  onClose,
  onSave,
  onSaveSecret,
  onDeleteSecret,
  saving = false,
}: Props) {
  const [enabled, setEnabled] = useState(provider.enabled);
  const [priority, setPriority] = useState(String(provider.priority));
  const [baseUrl, setBaseUrl] = useState(provider.base_url ?? '');
  const [feedUrls, setFeedUrls] = useState(provider.feed_urls.join('\n'));
  const [timeout, setTimeoutValue] = useState(String(provider.timeout_seconds));
  const [maxRetries, setMaxRetries] = useState(String(provider.max_retries));
  const [circuitBreaker, setCircuitBreaker] = useState(provider.circuit_breaker_enabled);
  const [knownDays, setKnownDays] = useState(provider.cache_ttl.known_days?.toString() ?? '');
  const [unknownHours, setUnknownHours] = useState(provider.cache_ttl.unknown_hours?.toString() ?? '');
  const [failureMinutes, setFailureMinutes] = useState(provider.cache_ttl.failure_minutes?.toString() ?? '');
  const [deprecatedDays, setDeprecatedDays] = useState(provider.cache_ttl.deprecated_days?.toString() ?? '');
  const [configText, setConfigText] = useState(JSON.stringify(provider.config ?? {}, null, 2));
  const [secretValue, setSecretValue] = useState('');

  useEffect(() => {
    setEnabled(provider.enabled);
    setPriority(String(provider.priority));
    setBaseUrl(provider.base_url ?? '');
    setFeedUrls(provider.feed_urls.join('\n'));
    setTimeoutValue(String(provider.timeout_seconds));
    setMaxRetries(String(provider.max_retries));
    setCircuitBreaker(provider.circuit_breaker_enabled);
    setKnownDays(provider.cache_ttl.known_days?.toString() ?? '');
    setUnknownHours(provider.cache_ttl.unknown_hours?.toString() ?? '');
    setFailureMinutes(provider.cache_ttl.failure_minutes?.toString() ?? '');
    setDeprecatedDays(provider.cache_ttl.deprecated_days?.toString() ?? '');
    setConfigText(JSON.stringify(provider.config ?? {}, null, 2));
    setSecretValue('');
  }, [provider]);

  const secretName = useMemo(() => providerSpecificSecretName(provider), [provider]);

  const numberOrNull = (value: string) => {
    const trimmed = value.trim();
    return trimmed ? Number(trimmed) : null;
  };

  const save = async () => {
    let config: Record<string, unknown> = {};
    try {
      config = configText.trim() ? JSON.parse(configText) : {};
    } catch {
      config = {};
    }
    await onSave(provider.provider_key, {
      enabled,
      priority: Number(priority),
      base_url: baseUrl.trim() || null,
      feed_urls: feedUrls.split('\n').map((line) => line.trim()).filter(Boolean),
      config,
      timeout_seconds: Number(timeout),
      max_retries: Number(maxRetries),
      circuit_breaker_enabled: circuitBreaker,
      cache_ttl_known_days: numberOrNull(knownDays),
      cache_ttl_unknown_hours: numberOrNull(unknownHours),
      cache_ttl_failure_minutes: numberOrNull(failureMinutes),
      cache_ttl_deprecated_days: numberOrNull(deprecatedDays),
    });
  };

  const hasFeedUrls = provider.provider_type === 'openeox';
  const hasSecret = ['xeol_api', 'repository_health'].includes(provider.provider_key);

  return (
    <aside className="fixed right-0 top-0 z-50 flex h-dvh w-full max-w-xl flex-col border-l border-border bg-background shadow-2xl">
      <div className="flex items-center justify-between border-b border-border px-5 py-4">
        <div>
          <h2 className="text-base font-semibold text-hcl-navy">{provider.display_name}</h2>
          <p className="text-xs text-hcl-muted">{provider.provider_key}</p>
        </div>
        <Button variant="ghost" size="icon" onClick={onClose} aria-label="Close">
          <X className="h-4 w-4" />
        </Button>
      </div>

      <div className="flex-1 space-y-5 overflow-y-auto px-5 py-5">
        <label className="flex items-center gap-2 text-sm font-medium text-hcl-navy">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Enabled
        </label>

        <div className="grid grid-cols-2 gap-4">
          <Field label="Priority" value={priority} onChange={setPriority} type="number" min={1} max={1000} />
          <Field label="Timeout seconds" value={timeout} onChange={setTimeoutValue} type="number" min={1} max={60} />
          <Field label="Max retries" value={maxRetries} onChange={setMaxRetries} type="number" min={0} max={10} />
          <label className="flex items-end gap-2 pb-2 text-sm font-medium text-hcl-navy">
            <input type="checkbox" checked={circuitBreaker} onChange={(e) => setCircuitBreaker(e.target.checked)} />
            Circuit breaker
          </label>
        </div>

        <Field label="Base URL" value={baseUrl} onChange={setBaseUrl} />

        {hasFeedUrls && (
          <label className="block text-sm font-medium text-hcl-navy">
            Feed URLs
            <textarea
              value={feedUrls}
              onChange={(e) => setFeedUrls(e.target.value)}
              className="mt-1 min-h-28 w-full rounded-md border border-border bg-background p-2 text-sm"
            />
          </label>
        )}

        {provider.provider_key === 'xeol_db' && (
          <label className="block text-sm font-medium text-hcl-navy">
            Configuration JSON
            <textarea
              value={configText}
              onChange={(e) => setConfigText(e.target.value)}
              className="mt-1 min-h-28 w-full rounded-md border border-border bg-background p-2 font-mono text-xs"
            />
          </label>
        )}

        {provider.provider_key === 'package_registry' && (
          <RegistryConfig configText={configText} setConfigText={setConfigText} />
        )}

        {provider.provider_key === 'repository_health' && (
          <RepositoryConfig configText={configText} setConfigText={setConfigText} />
        )}

        <div>
          <h3 className="text-sm font-semibold text-hcl-navy">Cache TTL</h3>
          <div className="mt-2 grid grid-cols-2 gap-4">
            <Field label="Known days" value={knownDays} onChange={setKnownDays} type="number" />
            <Field label="Unknown hours" value={unknownHours} onChange={setUnknownHours} type="number" />
            <Field label="Failure minutes" value={failureMinutes} onChange={setFailureMinutes} type="number" />
            <Field label="Deprecated days" value={deprecatedDays} onChange={setDeprecatedDays} type="number" />
          </div>
        </div>

        {hasSecret && (
          <div className="rounded-md border border-border p-3">
            <div className="flex items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-semibold text-hcl-navy">Secret</h3>
                <p className="text-xs text-hcl-muted">{provider.secret_preview ?? 'No secret saved'}</p>
              </div>
              {provider.has_secret && (
                <Button variant="ghost" size="sm" onClick={() => onDeleteSecret(provider.provider_key, secretName)}>
                  <Trash2 className="h-3.5 w-3.5" />
                  Delete
                </Button>
              )}
            </div>
            <div className="mt-3 flex gap-2">
              <input
                type="password"
                value={secretValue}
                onChange={(e) => setSecretValue(e.target.value)}
                className="h-9 flex-1 rounded-md border border-border bg-background px-2 text-sm"
              />
              <Button
                size="sm"
                onClick={() => onSaveSecret(provider.provider_key, secretName, secretValue)}
                disabled={!secretValue.trim()}
              >
                <KeyRound className="h-3.5 w-3.5" />
                Save
              </Button>
            </div>
          </div>
        )}
      </div>

      <div className="flex justify-end gap-2 border-t border-border px-5 py-4">
        <Button variant="secondary" onClick={onClose}>Cancel</Button>
        <Button onClick={save} loading={saving}>
          <Save className="h-4 w-4" />
          Save
        </Button>
      </div>
    </aside>
  );
}

function Field({
  label,
  value,
  onChange,
  type = 'text',
  min,
  max,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  type?: string;
  min?: number;
  max?: number;
}) {
  return (
    <label className="block text-sm font-medium text-hcl-navy">
      {label}
      <input
        type={type}
        min={min}
        max={max}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="mt-1 h-9 w-full rounded-md border border-border bg-background px-2 text-sm"
      />
    </label>
  );
}

function RegistryConfig({ configText, setConfigText }: { configText: string; setConfigText: (value: string) => void }) {
  return (
    <label className="block text-sm font-medium text-hcl-navy">
      Registry configuration JSON
      <textarea
        value={configText}
        onChange={(e) => setConfigText(e.target.value)}
        className="mt-1 min-h-28 w-full rounded-md border border-border bg-background p-2 font-mono text-xs"
      />
    </label>
  );
}

function RepositoryConfig({ configText, setConfigText }: { configText: string; setConfigText: (value: string) => void }) {
  return (
    <label className="block text-sm font-medium text-hcl-navy">
      Repository health JSON
      <textarea
        value={configText}
        onChange={(e) => setConfigText(e.target.value)}
        className="mt-1 min-h-28 w-full rounded-md border border-border bg-background p-2 font-mono text-xs"
      />
    </label>
  );
}
