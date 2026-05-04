'use client';

import { ExternalLink, Loader2, Sparkles, X } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import {
  useCreateAiCredential,
  useProviderCatalog,
  useTestConnection,
} from '@/hooks/useAiCredentials';
import type {
  AiProviderCatalogEntry,
  AiTier,
} from '@/types/ai';
import { TestResultDisplay } from './TestResultDisplay';

interface AddProviderDialogProps {
  open: boolean;
  onClose: () => void;
}

/**
 * Phase 3 §3.2 — single-form "Add provider" dialog.
 *
 * Three sections (provider type / configure / verify) presented as a
 * scrolling form (not a wizard). Test-connection is mandatory before
 * Save — the Save button is disabled until ``testResult.success``.
 *
 * Form fields adapt to provider type via ``ProviderFieldsRenderer``
 * (inlined here for compactness):
 *
 *   * cloud + paid    → API key + model dropdown
 *   * cloud + free    → API key + model dropdown + tier select
 *   * local           → base URL + model dropdown / free-text
 *   * custom          → base URL + optional API key + free-text model
 *                       + optional rate / cost overrides
 */
export function AddProviderDialog({ open, onClose }: AddProviderDialogProps) {
  const { data: catalog } = useProviderCatalog();
  const { unsaved: testMut } = useTestConnection();
  const createMut = useCreateAiCredential();

  const [providerName, setProviderName] = useState<string>('anthropic');
  const [apiKey, setApiKey] = useState<string>('');
  const [showKey, setShowKey] = useState(false);
  const [baseUrl, setBaseUrl] = useState<string>('');
  const [defaultModel, setDefaultModel] = useState<string>('');
  const [tier, setTier] = useState<AiTier>('paid');
  const [costIn, setCostIn] = useState<string>('0');
  const [costOut, setCostOut] = useState<string>('0');
  const [isLocal, setIsLocal] = useState<boolean>(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  const entry: AiProviderCatalogEntry | undefined = useMemo(
    () => (catalog ?? []).find((e) => e.name === providerName),
    [catalog, providerName],
  );

  // Reset form when the active provider changes.
  useEffect(() => {
    if (!entry) return;
    setApiKey('');
    setShowKey(false);
    setBaseUrl(entry.name === 'ollama' ? 'http://localhost:11434' : '');
    const firstModel = entry.available_models[0]?.name ?? '';
    setDefaultModel(firstModel);
    setTier(entry.supports_free_tier ? 'free' : 'paid');
    setIsLocal(entry.is_local);
    testMut.reset();
    setSubmitError(null);
  // ``testMut`` is stable across renders; we deliberately exclude it.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [entry?.name]);

  if (!open) return null;

  const formValid = (() => {
    if (!entry) return false;
    if (entry.requires_api_key && !apiKey.trim()) return false;
    if (entry.requires_base_url && !baseUrl.trim()) return false;
    if (!defaultModel.trim() && entry.name !== 'custom_openai') return false;
    if (entry.name === 'custom_openai' && !defaultModel.trim()) return false;
    return true;
  })();

  const canTest = formValid && !testMut.isPending;
  const canSave =
    formValid && testMut.data?.success === true && !createMut.isPending;

  const handleTest = () => {
    if (!entry) return;
    setSubmitError(null);
    testMut.mutate({
      provider_name: providerName,
      api_key: entry.requires_api_key ? apiKey.trim() : null,
      base_url: entry.requires_base_url ? baseUrl.trim() : null,
      default_model: defaultModel.trim() || null,
      tier,
      cost_per_1k_input_usd: Number.parseFloat(costIn) || 0,
      cost_per_1k_output_usd: Number.parseFloat(costOut) || 0,
      is_local: isLocal,
    });
  };

  const handleSave = () => {
    if (!entry || !canSave) return;
    setSubmitError(null);
    createMut.mutate(
      {
        provider_name: providerName,
        label: 'default',
        api_key: entry.requires_api_key ? apiKey.trim() : null,
        base_url: entry.requires_base_url ? baseUrl.trim() : null,
        default_model: defaultModel.trim() || null,
        tier,
        cost_per_1k_input_usd: Number.parseFloat(costIn) || 0,
        cost_per_1k_output_usd: Number.parseFloat(costOut) || 0,
        is_local: isLocal,
        enabled: true,
      },
      {
        onSuccess: () => onClose(),
        onError: (err) => setSubmitError(err.message ?? 'Save failed'),
      },
    );
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="ai-add-provider-heading"
      className="fixed inset-0 z-40 flex items-start justify-center bg-black/40 px-4 py-12"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="w-full max-w-xl rounded-lg border border-border-subtle bg-surface p-6 shadow-card">
        <header className="mb-4 flex items-start justify-between">
          <h2
            id="ai-add-provider-heading"
            className="flex items-center gap-2 text-lg font-semibold text-hcl-navy"
          >
            <Sparkles className="h-5 w-5 text-primary" aria-hidden />
            Add AI provider
          </h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close dialog"
            className="rounded-md p-1 text-hcl-muted hover:bg-surface-muted"
          >
            <X className="h-4 w-4" aria-hidden />
          </button>
        </header>

        {/* 1. Choose provider */}
        <fieldset className="mb-4">
          <legend className="text-xs font-semibold uppercase tracking-wider text-hcl-muted">
            1. Choose provider
          </legend>
          <select
            value={providerName}
            onChange={(e) => setProviderName(e.target.value)}
            aria-label="Provider"
            className="mt-1 w-full rounded-md border border-border-subtle bg-surface px-3 py-2 text-sm text-hcl-navy"
          >
            {(catalog ?? []).map((c) => (
              <option key={c.name} value={c.name}>
                {c.display_name}
                {c.supports_free_tier ? ' — free tier available ⭐' : ''}
                {c.is_local ? ' — local' : ''}
              </option>
            ))}
          </select>
          {entry?.notes ? (
            <p className="mt-1 text-xs text-hcl-muted">{entry.notes}</p>
          ) : null}
        </fieldset>

        {/* 2. Configure — provider-specific fields */}
        {entry ? (
          <fieldset className="mb-4 space-y-3">
            <legend className="text-xs font-semibold uppercase tracking-wider text-hcl-muted">
              2. Configure
            </legend>

            {entry.requires_api_key ? (
              <div>
                <label className="text-xs font-medium text-hcl-navy" htmlFor="ai-add-api-key">
                  API key
                </label>
                <div className="mt-1 flex gap-2">
                  <input
                    id="ai-add-api-key"
                    type={showKey ? 'text' : 'password'}
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                    autoComplete="off"
                    spellCheck={false}
                    placeholder={entry.api_key_url ? 'Paste your key here' : ''}
                    className="flex-1 rounded-md border border-border-subtle bg-surface px-3 py-2 font-mono text-sm"
                  />
                  <button
                    type="button"
                    onClick={() => setShowKey((v) => !v)}
                    className="rounded-md border border-border-subtle bg-surface px-2 py-1 text-xs text-hcl-muted hover:bg-surface-muted"
                    aria-label={showKey ? 'Hide API key' : 'Show API key'}
                  >
                    {showKey ? 'Hide' : 'Show'}
                  </button>
                  {entry.api_key_url ? (
                    <a
                      href={entry.api_key_url}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="inline-flex items-center gap-1 rounded-md border border-border-subtle bg-surface px-2 py-1 text-xs text-hcl-navy hover:bg-surface-muted"
                    >
                      Get a key <ExternalLink className="h-3 w-3" aria-hidden />
                    </a>
                  ) : null}
                </div>
              </div>
            ) : null}

            {entry.requires_base_url ? (
              <div>
                <label className="text-xs font-medium text-hcl-navy" htmlFor="ai-add-base-url">
                  Base URL
                </label>
                <input
                  id="ai-add-base-url"
                  type="url"
                  value={baseUrl}
                  onChange={(e) => setBaseUrl(e.target.value)}
                  spellCheck={false}
                  placeholder={entry.name === 'ollama' ? 'http://localhost:11434' : 'https://your-endpoint/v1'}
                  className="mt-1 w-full rounded-md border border-border-subtle bg-surface px-3 py-2 font-mono text-sm"
                />
                {entry.name === 'custom_openai' ? (
                  <p className="mt-1 text-xs text-hcl-muted">
                    Must start with <code>https://</code> or <code>http://localhost</code>.
                    Plaintext public URLs are rejected.
                  </p>
                ) : null}
              </div>
            ) : null}

            <div>
              <label className="text-xs font-medium text-hcl-navy" htmlFor="ai-add-model">
                Model
              </label>
              {entry.available_models.length > 0 ? (
                <select
                  id="ai-add-model"
                  value={defaultModel}
                  onChange={(e) => {
                    setDefaultModel(e.target.value);
                    const m = entry.available_models.find((x) => x.name === e.target.value);
                    if (m && entry.supports_free_tier) {
                      setTier(m.default_tier);
                    }
                  }}
                  className="mt-1 w-full rounded-md border border-border-subtle bg-surface px-3 py-2 text-sm"
                >
                  {entry.available_models.map((m) => (
                    <option key={m.name} value={m.name}>
                      {m.display_name}
                      {m.notes ? ` — ${m.notes}` : ''}
                    </option>
                  ))}
                </select>
              ) : (
                <input
                  id="ai-add-model"
                  type="text"
                  value={defaultModel}
                  onChange={(e) => setDefaultModel(e.target.value)}
                  spellCheck={false}
                  placeholder="e.g. llama-3-70b"
                  className="mt-1 w-full rounded-md border border-border-subtle bg-surface px-3 py-2 font-mono text-sm"
                />
              )}
            </div>

            {entry.supports_free_tier ? (
              <div>
                <label className="text-xs font-medium text-hcl-navy" htmlFor="ai-add-tier">
                  Tier
                </label>
                <select
                  id="ai-add-tier"
                  value={tier}
                  onChange={(e) => setTier(e.target.value as AiTier)}
                  className="mt-1 w-full rounded-md border border-border-subtle bg-surface px-3 py-2 text-sm"
                >
                  <option value="free">
                    Free
                    {entry.free_tier_rate_limit_rpm
                      ? ` — ${entry.free_tier_rate_limit_rpm} req/min`
                      : ''}
                  </option>
                  <option value="paid">Paid</option>
                </select>
              </div>
            ) : null}

            {entry.name === 'custom_openai' ? (
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label
                    className="text-xs font-medium text-hcl-navy"
                    htmlFor="ai-add-cost-in"
                  >
                    Cost per 1k input ($)
                  </label>
                  <input
                    id="ai-add-cost-in"
                    type="number"
                    min="0"
                    step="0.000001"
                    value={costIn}
                    onChange={(e) => setCostIn(e.target.value)}
                    className="mt-1 w-full rounded-md border border-border-subtle bg-surface px-3 py-2 font-mono text-sm"
                  />
                </div>
                <div>
                  <label
                    className="text-xs font-medium text-hcl-navy"
                    htmlFor="ai-add-cost-out"
                  >
                    Cost per 1k output ($)
                  </label>
                  <input
                    id="ai-add-cost-out"
                    type="number"
                    min="0"
                    step="0.000001"
                    value={costOut}
                    onChange={(e) => setCostOut(e.target.value)}
                    className="mt-1 w-full rounded-md border border-border-subtle bg-surface px-3 py-2 font-mono text-sm"
                  />
                </div>
                <label className="col-span-2 inline-flex items-center gap-2 text-xs text-hcl-navy">
                  <input
                    type="checkbox"
                    checked={isLocal}
                    onChange={(e) => setIsLocal(e.target.checked)}
                  />
                  Treat as local (cost reported as $0 in ledger)
                </label>
              </div>
            ) : null}
          </fieldset>
        ) : null}

        {/* 3. Verify */}
        <fieldset className="mb-4">
          <legend className="text-xs font-semibold uppercase tracking-wider text-hcl-muted">
            3. Verify
          </legend>
          <div className="mt-1 flex items-center gap-2">
            <button
              type="button"
              onClick={handleTest}
              disabled={!canTest}
              className="inline-flex items-center gap-1 rounded-md border border-border-subtle bg-surface px-3 py-1.5 text-sm font-medium text-hcl-navy hover:bg-surface-muted disabled:cursor-not-allowed disabled:opacity-50"
            >
              {testMut.isPending ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
              ) : null}
              Test connection
            </button>
            <TestResultDisplay result={testMut.data ?? null} testing={testMut.isPending} />
          </div>
        </fieldset>

        {submitError ? (
          <p role="alert" className="mb-3 rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-800">
            {submitError}
          </p>
        ) : null}

        <footer className="flex items-center justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border border-border-subtle bg-surface px-3 py-1.5 text-sm text-hcl-navy hover:bg-surface-muted"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleSave}
            disabled={!canSave}
            className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white shadow-elev-1 hover:bg-hcl-dark disabled:cursor-not-allowed disabled:opacity-50"
            title={
              !formValid
                ? 'Fill in the required fields first'
                : !testMut.data?.success
                  ? 'Test connection must pass before saving'
                  : undefined
            }
          >
            {createMut.isPending ? 'Saving…' : 'Save provider'}
          </button>
        </footer>
      </div>
    </div>
  );
}
