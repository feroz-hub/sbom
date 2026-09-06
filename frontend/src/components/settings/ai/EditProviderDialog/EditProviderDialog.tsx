'use client';

import { Loader2, Pencil, X } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import {
  useProviderCatalog,
  useTestConnection,
  useUpdateAiCredential,
} from '@/hooks/useAiCredentials';
import type {
  AiCredential,
  AiCredentialUpdateRequest,
  AiTier,
} from '@/types/ai';
import { TestResultDisplay } from '../AddProviderDialog/TestResultDisplay';
import { getApiErrorMessage } from '@/lib/notifications';
import { customOpenAiBaseUrlError } from '@/lib/aiProviderValidation';

interface EditProviderDialogProps {
  credential: AiCredential | null;
  onClose: () => void;
}

/**
 * Edit dialog. Same shape as AddProviderDialog but:
 *
 *   * Provider type is fixed (the row already exists).
 *   * API key field is empty with placeholder "Leave blank to keep existing"
 *     — Phase 3 §3.4 hard rule.
 *   * Test-connection is optional (not mandatory) for edits — saved
 *     credentials may have a successful prior test.
 */
export function EditProviderDialog({ credential, onClose }: EditProviderDialogProps) {
  const { data: catalog } = useProviderCatalog();
  const { unsaved: testMut } = useTestConnection();
  const updateMut = useUpdateAiCredential();

  const entry = useMemo(
    () => (catalog ?? []).find((e) => e.name === credential?.provider_name),
    [catalog, credential?.provider_name],
  );

  const [apiKey, setApiKey] = useState('');
  const [label, setLabel] = useState('default');
  const [showKey, setShowKey] = useState(false);
  const [baseUrl, setBaseUrl] = useState('');
  const [defaultModel, setDefaultModel] = useState('');
  const [tier, setTier] = useState<AiTier>('paid');
  const [costIn, setCostIn] = useState('0');
  const [costOut, setCostOut] = useState('0');
  const [isLocal, setIsLocal] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  useEffect(() => {
    if (!credential) return;
    setApiKey('');
    setLabel(credential.label);
    setShowKey(false);
    setBaseUrl(credential.base_url ?? '');
    setDefaultModel(credential.default_model ?? '');
    setTier((credential.tier === 'free' ? 'free' : 'paid'));
    setCostIn(String(credential.cost_per_1k_input_usd));
    setCostOut(String(credential.cost_per_1k_output_usd));
    setIsLocal(credential.is_local);
    testMut.reset();
    setSubmitError(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [credential?.id]);

  if (!credential) return null;

  const baseUrlError = entry?.name === 'custom_openai'
    ? customOpenAiBaseUrlError(baseUrl)
    : null;
  const formValid = Boolean(label.trim()) && Boolean(defaultModel.trim())
    && (!entry?.requires_base_url || Boolean(baseUrl.trim()))
    && !baseUrlError;

  const handleTest = () => {
    if (!entry) return;
    setSubmitError(null);
    testMut.mutate({
      credential_id: credential.id,
      provider_name: credential.provider_name,
      // The API resolves the existing encrypted key server-side when this
      // is blank, while still testing the candidate URL/model values.
      api_key: apiKey.trim() || null,
      base_url: baseUrl.trim() || null,
      default_model: defaultModel.trim() || null,
      tier,
      cost_per_1k_input_usd: Number.parseFloat(costIn) || 0,
      cost_per_1k_output_usd: Number.parseFloat(costOut) || 0,
      is_local: isLocal,
      max_concurrent: credential.max_concurrent,
      rate_per_minute: credential.rate_per_minute,
    });
  };

  const handleSave = () => {
    setSubmitError(null);
    const body: AiCredentialUpdateRequest = {
      label: label.trim(),
      base_url: baseUrl.trim() || null,
      default_model: defaultModel.trim(),
      tier,
      cost_per_1k_input_usd: Number.parseFloat(costIn) || 0,
      cost_per_1k_output_usd: Number.parseFloat(costOut) || 0,
      is_local: isLocal,
    };
    if (apiKey.trim()) {
      body.api_key = apiKey.trim();
    }
    updateMut.mutate(
      { id: credential.id, body },
      {
        onSuccess: () => onClose(),
        onError: (error) => setSubmitError(getApiErrorMessage(error, 'Provider update failed.')),
      },
    );
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="ai-edit-provider-heading"
      className="fixed inset-0 z-40 flex items-start justify-center bg-black/40 px-4 py-12"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="w-full max-w-xl rounded-lg border border-border-subtle bg-surface p-6 shadow-card">
        <header className="mb-4 flex items-start justify-between">
          <h2
            id="ai-edit-provider-heading"
            className="flex items-center gap-2 text-lg font-semibold text-hcl-navy"
          >
            <Pencil className="h-5 w-5 text-primary" aria-hidden />
            Edit {entry?.display_name ?? credential.provider_name}
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

        <div className="space-y-3">
          <div>
            <label className="text-xs font-medium text-hcl-navy" htmlFor="ai-edit-label">
              Credential label
            </label>
            <input
              id="ai-edit-label"
              type="text"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              maxLength={64}
              className="mt-1 w-full rounded-md border border-border-subtle bg-surface px-3 py-2 text-sm"
            />
          </div>
          {entry?.requires_api_key || entry?.name === 'custom_openai' ? (
            <div>
              <label className="text-xs font-medium text-hcl-navy" htmlFor="ai-edit-api-key">
                API key{entry.requires_api_key ? '' : ' (optional)'}
              </label>
              <div className="mt-1 flex gap-2">
                <input
                  id="ai-edit-api-key"
                  type={showKey ? 'text' : 'password'}
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  autoComplete="off"
                  spellCheck={false}
                  placeholder={`Leave blank to keep existing (${credential.api_key_preview ?? 'set'})`}
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
              </div>
              <p className="mt-1 text-xs text-hcl-muted">
                Current key: <span className="font-mono">{credential.api_key_preview ?? '—'}</span>
              </p>
            </div>
          ) : null}

          {entry?.requires_base_url ? (
            <div>
              <label className="text-xs font-medium text-hcl-navy" htmlFor="ai-edit-base-url">
                Base URL
              </label>
              <input
                id="ai-edit-base-url"
                type="url"
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                spellCheck={false}
                className="mt-1 w-full rounded-md border border-border-subtle bg-surface px-3 py-2 font-mono text-sm"
              />
              {entry.name === 'custom_openai' ? (
                <p className={`mt-1 text-xs ${baseUrlError ? 'text-red-700' : 'text-hcl-muted'}`}>
                  {baseUrlError ?? 'HTTPS is required remotely; local HTTP is allowed.'}
                </p>
              ) : null}
            </div>
          ) : null}

          <div>
            <label className="text-xs font-medium text-hcl-navy" htmlFor="ai-edit-model">
              Model
            </label>
            {entry && entry.available_models.length > 0 ? (
              <select
                id="ai-edit-model"
                value={defaultModel}
                onChange={(e) => setDefaultModel(e.target.value)}
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
                id="ai-edit-model"
                type="text"
                value={defaultModel}
                onChange={(e) => setDefaultModel(e.target.value)}
                spellCheck={false}
                className="mt-1 w-full rounded-md border border-border-subtle bg-surface px-3 py-2 font-mono text-sm"
              />
            )}
          </div>

          {entry?.supports_free_tier ? (
            <div>
              <label className="text-xs font-medium text-hcl-navy" htmlFor="ai-edit-tier">
                Tier
              </label>
              <select
                id="ai-edit-tier"
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

          {entry?.name === 'custom_openai' ? (
            <div className="grid grid-cols-2 gap-3">
              <label className="text-xs text-hcl-navy">
                Cost per 1k input ($)
                <input type="number" min="0" step="0.000001" value={costIn} onChange={(e) => setCostIn(e.target.value)} className="mt-1 w-full rounded-md border border-border-subtle bg-surface px-3 py-2 font-mono text-sm" />
              </label>
              <label className="text-xs text-hcl-navy">
                Cost per 1k output ($)
                <input type="number" min="0" step="0.000001" value={costOut} onChange={(e) => setCostOut(e.target.value)} className="mt-1 w-full rounded-md border border-border-subtle bg-surface px-3 py-2 font-mono text-sm" />
              </label>
              <label className="col-span-2 inline-flex items-center gap-2 text-xs text-hcl-navy">
                <input type="checkbox" checked={isLocal} onChange={(e) => setIsLocal(e.target.checked)} />
                Treat as local (cost reported as $0 in ledger)
              </label>
            </div>
          ) : null}

          <div>
            <button
              type="button"
              onClick={handleTest}
              disabled={testMut.isPending || !formValid}
              className="inline-flex items-center gap-1 rounded-md border border-border-subtle bg-surface px-3 py-1.5 text-sm text-hcl-navy hover:bg-surface-muted disabled:cursor-progress disabled:opacity-60"
            >
              {testMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden /> : null}
              Test connection (optional)
            </button>
            <div className="mt-2">
              <TestResultDisplay result={testMut.data ?? null} testing={testMut.isPending} />
            </div>
          </div>
        </div>

        {submitError ? (
          <p role="alert" className="mt-3 rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-800">
            {submitError}
          </p>
        ) : null}

        <footer className="mt-4 flex items-center justify-end gap-2">
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
            disabled={updateMut.isPending || !formValid}
            className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white shadow-elev-1 hover:bg-hcl-dark disabled:cursor-not-allowed disabled:opacity-50"
          >
            {updateMut.isPending ? 'Saving…' : 'Save changes'}
          </button>
        </footer>
      </div>
    </div>
  );
}
