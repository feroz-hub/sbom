'use client';

import { FlaskConical, RefreshCw } from 'lucide-react';
import {
  useAiProviderModels,
  useRefreshAiProviderModels,
  useSelectAiProviderModel,
  useTestAiProviderModel,
} from '@/hooks/useAiCredentials';

interface Props {
  credentialId: number;
  providerName: string;
  enabled: boolean;
}

function status(value: boolean | null): string {
  return value === true ? 'Available' : value === false ? 'Unavailable' : 'Not yet verified';
}

function capability(label: string, value: boolean | null) {
  if (value == null) return null;
  return (
    <span className={`rounded px-1.5 py-0.5 text-[10px] ${value ? 'bg-emerald-50 text-emerald-700' : 'bg-red-50 text-red-700'}`}>
      {label}: {value ? 'yes' : 'no'}
    </span>
  );
}

export function ProviderModels({ credentialId, providerName, enabled }: Props) {
  const models = useAiProviderModels(credentialId);
  const refresh = useRefreshAiProviderModels(credentialId);
  const select = useSelectAiProviderModel(credentialId);
  const test = useTestAiProviderModel(credentialId);

  return (
    <section className="mt-4 border-t border-border-subtle pt-3" aria-label={`${providerName} models`}>
      <div className="flex items-center justify-between gap-3">
        <h4 className="text-xs font-semibold uppercase tracking-wide text-hcl-muted">Available models</h4>
        <button
          type="button"
          disabled={!enabled || refresh.isPending}
          onClick={() => refresh.mutate()}
          className="inline-flex items-center gap-1 rounded-md border border-border-subtle px-2 py-1 text-xs text-hcl-navy hover:bg-surface-muted disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${refresh.isPending ? 'animate-spin' : ''}`} aria-hidden />
          {refresh.isPending ? 'Refreshing…' : 'Refresh models'}
        </button>
      </div>

      {refresh.data ? (
        <p className="mt-2 text-xs text-emerald-700" role="status">
          Found {refresh.data.discovered} models; {refresh.data.created} new, {refresh.data.unavailable} now unavailable.
        </p>
      ) : null}
      {refresh.error ? <p className="mt-2 text-xs text-red-700" role="alert">{refresh.error.message}</p> : null}
      {test.data ? (
        <p className={`mt-2 text-xs ${test.data.success ? 'text-emerald-700' : 'text-red-700'}`} role="status">
          {test.data.success ? 'Model test passed.' : test.data.error_message ?? 'Model test failed.'}
        </p>
      ) : null}

      {models.isLoading ? <p className="mt-2 text-xs text-hcl-muted">Loading models…</p> : null}
      {models.error ? <p className="mt-2 text-xs text-red-700">Unable to load model registry.</p> : null}
      {models.data?.length === 0 ? (
        <p className="mt-2 text-xs text-hcl-muted">No models discovered yet. Refresh to query the provider.</p>
      ) : null}
      {models.data && models.data.length > 0 ? (
        <div className="mt-2 overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="text-hcl-muted">
              <tr><th className="py-1 pr-3 font-medium">Model</th><th className="py-1 pr-3 font-medium">Status</th><th className="py-1 font-medium">Actions</th></tr>
            </thead>
            <tbody>
              {models.data.map((model) => (
                <tr key={model.id} className="border-t border-border-subtle align-top">
                  <td className="py-2 pr-3">
                    <span className="font-mono text-hcl-navy">{model.runtime_model_id}</span>
                    {model.provider_model_id !== model.runtime_model_id ? <span className="block text-[10px] text-hcl-muted">Provider ID: {model.provider_model_id}</span> : null}
                    <span className="mt-1 flex flex-wrap gap-1">
                      {capability('chat', model.supports_chat)}
                      {capability('JSON', model.supports_structured_output)}
                      {capability('tools', model.supports_tools)}
                      {capability('stream', model.supports_streaming)}
                    </span>
                    {model.context_window || model.max_output_tokens ? (
                      <span className="mt-1 block text-[10px] text-hcl-muted">
                        {model.context_window ? `Context ${model.context_window.toLocaleString()}` : ''}
                        {model.context_window && model.max_output_tokens ? ' · ' : ''}
                        {model.max_output_tokens ? `Output ${model.max_output_tokens.toLocaleString()}` : ''}
                      </span>
                    ) : null}
                  </td>
                  <td className="py-2 pr-3">
                    <span className={model.is_available === false ? 'text-red-700' : model.is_available === true ? 'text-emerald-700' : 'text-amber-700'}>{status(model.is_available)}</span>
                    {model.is_selected ? <span className="block font-medium text-primary">Active</span> : null}
                    {model.last_discovered_at ? <time className="block text-[10px] text-hcl-muted" dateTime={model.last_discovered_at}>{new Date(model.last_discovered_at).toLocaleString()}</time> : null}
                  </td>
                  <td className="py-2">
                    <div className="flex flex-wrap gap-1">
                      <button type="button" disabled={test.isPending} onClick={() => test.mutate(model.id)} className="inline-flex items-center gap-1 rounded border border-border-subtle px-1.5 py-1 hover:bg-surface-muted disabled:opacity-50">
                        <FlaskConical className="h-3 w-3" aria-hidden /> Test
                      </button>
                      <button type="button" disabled={model.is_selected || model.is_available !== true || select.isPending} onClick={() => select.mutate(model.id)} className="rounded bg-primary px-1.5 py-1 font-medium text-white disabled:opacity-40">Set active</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  );
}
