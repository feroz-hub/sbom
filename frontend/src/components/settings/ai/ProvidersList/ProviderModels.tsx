'use client';

import { useState } from 'react';
import { FlaskConical, RefreshCw } from 'lucide-react';
import { ConfirmDialog } from '@/components/ui/Dialog';
import type { AiProviderModel } from '@/types/ai';
import { useAiConfigurationScope } from '../ConfigurationScope';
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
  search?: string;
}
const actionClass =
  'inline-flex min-h-10 items-center justify-center gap-1 rounded-lg border border-border px-3 text-sm text-hcl-navy hover:bg-surface-muted disabled:opacity-50';
function capability(label: string, value: boolean | null) {
  return (
    <span className="rounded border border-border bg-surface-muted px-2 py-1 text-xs text-hcl-navy">
      {label}: {value == null ? 'unknown' : value ? 'yes' : 'no'}
    </span>
  );
}

export function ProviderModels({
  credentialId,
  providerName,
  enabled,
  search = '',
}: Props) {
  const { canTest, canUpdate = true, scope } = useAiConfigurationScope();
  const models = useAiProviderModels(credentialId);
  const refresh = useRefreshAiProviderModels(credentialId);
  const select = useSelectAiProviderModel(credentialId);
  const test = useTestAiProviderModel(credentialId);
  const [candidate, setCandidate] = useState<AiProviderModel | null>(null);
  const [copyStatus, setCopyStatus] = useState('');
  const filtered = models.data?.filter((m) =>
    [
      m.runtime_model_id,
      m.provider_model_id,
      m.display_name,
      m.provider_name,
    ].some((value) => value?.toLowerCase().includes(search.toLowerCase())),
  );
  const testModel = models.data?.find((m) => m.id === test.variables);

  return (
    <section
      className="min-w-0 rounded-xl border border-border bg-surface p-4 sm:p-5"
      aria-label={`${providerName} models`}
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="font-semibold text-hcl-navy">{providerName}</h3>
          <p className="mt-1 text-sm text-hcl-muted">
            {enabled
              ? 'Models and capabilities reported by this provider.'
              : 'Provider disabled. Enable it in Providers to refresh models.'}
          </p>
        </div>
        <button
          type="button"
          disabled={!canTest || !enabled || refresh.isPending}
          onClick={() => refresh.mutate()}
          className={actionClass}
        >
          <RefreshCw
            className={`h-4 w-4 ${refresh.isPending ? 'animate-spin' : ''}`}
            aria-hidden
          />
          {refresh.isPending ? 'Refreshing…' : 'Refresh models'}
        </button>
      </div>
      {refresh.isPending && (
        <p role="status" className="mt-3 text-hcl-muted">
          Discovering models; previous results remain below.
        </p>
      )}
      {refresh.data && (
        <p className="mt-3 text-hcl-navy" role="status">
          Found {refresh.data.discovered} models; {refresh.data.created} new,{' '}
          {refresh.data.unavailable} now unavailable.
        </p>
      )}
      {refresh.error && (
        <p className="mt-3 text-red-700 dark:text-red-300" role="alert">
          {refresh.error.message} Use Refresh models to retry.
        </p>
      )}
      {test.isPending && (
        <p className="mt-3 text-hcl-navy" role="status">
          Running model test: {testModel?.runtime_model_id}…
        </p>
      )}
      {test.data && (
        <p className="mt-3 text-hcl-navy" role="status">
          {testModel?.runtime_model_id}:{' '}
          {test.data.success
            ? 'Model test passed.'
            : (test.data.error_message ?? 'Model test failed.')}
        </p>
      )}
      {test.error && (
        <p className="mt-3 text-red-700 dark:text-red-300" role="alert">
          {testModel?.runtime_model_id}: {test.error.message}
        </p>
      )}
      {select.error && (
        <p className="mt-3 text-red-700 dark:text-red-300" role="alert">
          Unable to activate model: {select.error.message}
        </p>
      )}
      {select.isSuccess && (
        <p role="status" className="mt-3 text-hcl-navy">
          Active model updated.
        </p>
      )}
      {copyStatus && (
        <p role="status" className="mt-3 text-hcl-muted">
          {copyStatus}
        </p>
      )}
      {models.isLoading && (
        <p className="mt-4 animate-pulse text-hcl-muted" role="status">
          Loading models…
        </p>
      )}
      {models.error && (
        <p className="mt-3 text-red-700 dark:text-red-300" role="alert">
          Unable to load model registry.{' '}
          <button
            type="button"
            className="underline"
            onClick={() => models.refetch()}
          >
            Retry
          </button>
        </p>
      )}
      {models.data?.length === 0 && (
        <p className="mt-4 text-hcl-muted">
          No models discovered yet. Refresh to query the provider.
        </p>
      )}
      {models.data && models.data.length > 0 && filtered?.length === 0 && (
        <p className="mt-4 text-hcl-muted">No models match your search.</p>
      )}
      {filtered && filtered.length > 0 && (
        <table className="mt-4 block w-full table-fixed text-left text-sm md:table">
          <caption className="sr-only">Models for {providerName}</caption>
          <thead className="hidden bg-surface-muted text-hcl-muted md:table-header-group">
            <tr>
              <th scope="col" className="w-[42%] p-3 font-medium">
                Model and capabilities
              </th>
              <th scope="col" className="p-3 font-medium">
                Availability / activation
              </th>
              <th scope="col" className="p-3 font-medium">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="block md:table-row-group">
            {filtered.map((model) => (
              <tr
                key={model.id}
                className="block border-t border-border-subtle align-top md:table-row"
              >
                <td className="block min-w-0 p-3 md:table-cell">
                  {model.display_name && (
                    <span className="block font-medium text-hcl-navy">
                      {model.display_name}
                    </span>
                  )}
                  <span className="break-all font-mono text-hcl-navy">
                    {model.runtime_model_id}
                  </span>
                  {model.provider_model_id !== model.runtime_model_id && (
                    <span className="block break-all text-xs text-hcl-muted">
                      Provider ID: {model.provider_model_id}
                    </span>
                  )}
                  <details className="mt-2 text-hcl-muted">
                    <summary className="min-h-9 cursor-pointer rounded text-xs focus-visible:outline-primary">
                      Capabilities and details
                    </summary>
                    <div className="mt-2 flex flex-wrap gap-1">
                      {capability('chat', model.supports_chat)}
                      {capability('JSON', model.supports_structured_output)}
                      {capability('tools', model.supports_tools)}
                      {capability('stream', model.supports_streaming)}
                    </div>
                    <dl className="mt-3 space-y-1 text-xs">
                      {[
                        ['Discovered', model.discovered],
                        ['Accessible', model.accessible],
                        ['Generation verified', model.generation_verified],
                        ['Workload compatible', model.workload_compatible],
                        ['Active', model.is_selected],
                      ].map(([label, value]) => (
                        <div key={String(label)}>
                          <dt className="inline">{label}: </dt>
                          <dd className="inline">{value == null ? 'Not tested' : value ? 'Yes' : 'No'}</dd>
                        </div>
                      ))}
                      {model.last_test_error && <div role="status">{model.last_test_error}</div>}

                      <div>
                        <dt className="inline">Context tokens: </dt>
                        <dd className="inline">
                          {model.context_window?.toLocaleString() ?? 'Unknown'}
                        </dd>
                      </div>
                      <div>
                        <dt className="inline">Max output tokens: </dt>
                        <dd className="inline">
                          {model.max_output_tokens?.toLocaleString() ??
                            'Unknown'}
                        </dd>
                      </div>
                      <div>
                        <dt className="inline">Discovery source: </dt>
                        <dd className="inline break-all">
                          {model.discovery_source}
                        </dd>
                      </div>
                      <div>
                        <dt className="inline">Model enabled: </dt>
                        <dd className="inline">
                          {model.is_enabled ? 'Yes' : 'No'}
                        </dd>
                      </div>
                      <div>
                        <dt className="inline">Last model test: </dt>
                        <dd className="inline">
                          {model.last_test_success == null
                            ? 'Not tested'
                            : model.last_test_success
                              ? 'Succeeded'
                              : 'Failed'}
                        </dd>
                      </div>
                      {model.last_verified_at && (
                        <div>
                          Last tested:{' '}
                          <time
                            dateTime={model.last_verified_at}
                            title={model.last_verified_at}
                          >
                            {new Date(model.last_verified_at).toLocaleString()}
                          </time>
                        </div>
                      )}
                    </dl>
                    <button
                      type="button"
                      className={`${actionClass} mt-2`}
                      onClick={async () => {
                        try {
                          await navigator.clipboard.writeText(
                            model.provider_model_id,
                          );
                          setCopyStatus('Provider model ID copied.');
                        } catch {
                          setCopyStatus(
                            'Unable to copy. Select the model ID to copy it manually.',
                          );
                        }
                      }}
                    >
                      Copy model ID
                    </button>
                  </details>
                </td>
                <td className="block p-3 md:table-cell">
                  <span className="text-hcl-navy">
                    {model.is_available === true
                      ? 'Available'
                      : model.is_available === false
                        ? 'Unavailable'
                        : 'Unknown availability'}
                  </span>
                  <span
                    className={`mt-1 block font-medium ${model.is_selected ? 'text-link' : 'text-hcl-muted'}`}
                  >
                    {model.is_selected ? 'Active' : 'Inactive'}
                  </span>
                  <span className="mt-2 block text-xs text-hcl-muted">
                    Last discovered:{' '}
                    {model.last_discovered_at ? (
                      <time
                        dateTime={model.last_discovered_at}
                        title={model.last_discovered_at}
                      >
                        {new Date(model.last_discovered_at).toLocaleString()}
                      </time>
                    ) : (
                      'Unknown'
                    )}
                  </span>
                </td>
                <td className="block p-3 md:table-cell">
                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      disabled={!canTest || test.isPending}
                      onClick={() => test.mutate(model.id)}
                      className={actionClass}
                    >
                      <FlaskConical className="h-4 w-4" aria-hidden />
                      Test
                    </button>
                    {canUpdate && (
                      <button
                        type="button"
                        disabled={
                          model.is_selected ||
                          model.is_available !== true ||
                          select.isPending
                        }
                        onClick={() => setCandidate(model)}
                        className={actionClass}
                      >
                        {model.is_selected ? 'Active' : 'Set active'}
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <ConfirmDialog
        open={candidate !== null}
        onClose={() => {
          if (!select.isPending) setCandidate(null);
        }}
        title="Change active model?"
        message={`Use ${candidate?.runtime_model_id ?? ''} for ${providerName}? ${scope === 'platform' ? 'This affects tenants that inherit the platform configuration.' : 'This affects this tenant’s AI configuration.'}${select.error ? ` Unable to activate model: ${select.error.message}` : ''}`}
        confirmLabel="Confirm activation"
        variant="primary"
        loading={select.isPending}
        onConfirm={() => {
          if (candidate && !select.isPending)
            select.mutate(candidate.id, {
              onSuccess: () => setCandidate(null),
            });
        }}
      />
    </section>
  );
}
