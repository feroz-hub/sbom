'use client';

import { Sparkles } from 'lucide-react';
import { useMemo, useState } from 'react';
import { useAiCredentials, useProviderCatalog } from '@/hooks/useAiCredentials';
import type { AiCredential } from '@/types/ai';
import { ProviderCard } from './ProviderCard';
import { useAiConfigurationScope } from '../ConfigurationScope';

interface ProvidersListProps {
  onAdd: () => void;
  onEdit: (credential: AiCredential) => void;
  onManageModels: (credential: AiCredential) => void;
}

/**
 * Phase 3 §3.1 — the providers list section header + card stack.
 *
 * Shows banner state when no default is set (per §3.8) and an
 * onboarding card when the list is empty.
 */
export function ProvidersList({
  onAdd,
  onEdit,
  onManageModels,
}: ProvidersListProps) {
  const [search, setSearch] = useState('');
  const { canUpdate = true } = useAiConfigurationScope();
  const {
    data: credentials,
    isLoading,
    isError,
    error,
    refetch,
  } = useAiCredentials();
  const { data: catalog } = useProviderCatalog();

  const catalogByName = useMemo(() => {
    const map = new Map<string, NonNullable<typeof catalog>[number]>();
    for (const entry of catalog ?? []) {
      map.set(entry.name, entry);
    }
    return map;
  }, [catalog]);

  const hasDefault = (credentials ?? []).some((c) => c.is_default && c.enabled);
  const empty = !isLoading && !isError && (credentials?.length ?? 0) === 0;

  return (
    <section className="space-y-3" aria-labelledby="ai-providers-heading">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2
          id="ai-providers-heading"
          className="text-base font-semibold text-hcl-navy"
        >
          AI providers
        </h2>
        <label className="flex min-w-0 flex-col gap-1 text-sm text-hcl-muted">
          Search providers
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Name, label or model"
            className="min-h-10 w-full rounded-lg border border-border bg-surface px-3 text-hcl-navy"
          />
        </label>
      </div>

      {isLoading ? (
        <p className="rounded-md border border-border-subtle bg-surface p-4 text-sm text-hcl-muted">
          Loading providers…
        </p>
      ) : null}

      {isError ? (
        <div
          role="alert"
          className="rounded-md border border-red-200 bg-red-50 p-4 text-sm text-red-800"
        >
          Could not load providers:{' '}
          {(error as Error)?.message ?? 'unknown error'}.
          <button
            type="button"
            onClick={() => refetch()}
            className="ml-2 rounded-md border border-red-300 bg-red-100 px-2 py-0.5 text-xs"
          >
            Retry
          </button>
        </div>
      ) : null}

      {empty ? (
        <div className="rounded-lg border border-dashed border-border bg-surface-muted p-6 text-center">
          <Sparkles className="mx-auto h-6 w-6 text-primary" aria-hidden />
          <h3 className="mt-2 text-sm font-semibold text-hcl-navy">
            Add your first AI provider
          </h3>
          <p className="mt-1 text-sm text-hcl-muted">
            Connect a supported provider to configure AI models.
          </p>
          {canUpdate && (
            <button
              type="button"
              onClick={onAdd}
              className="mt-3 inline-flex items-center gap-1 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-white shadow-elev-1 hover:bg-hcl-dark"
            >
              Add provider
            </button>
          )}
        </div>
      ) : null}

      {!empty && (credentials ?? []).length > 0 && !hasDefault ? (
        <p
          role="alert"
          className="rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900"
        >
          No enabled saved provider is marked as default. Review the effective
          configuration above before changing defaults.
        </p>
      ) : null}

      {credentials &&
        credentials.length > 0 &&
        !credentials.some((c) =>
          [
            c.provider_name,
            c.label,
            c.default_model,
            catalogByName.get(c.provider_name)?.display_name,
          ].some((value) =>
            value?.toLowerCase().includes(search.toLowerCase()),
          ),
        ) && (
          <p role="status" className="p-4 text-hcl-muted">
            No providers match your search.
          </p>
        )}
      <div className="space-y-3">
        {(credentials ?? [])
          .filter((c) =>
            [
              c.provider_name,
              c.label,
              c.default_model,
              catalogByName.get(c.provider_name)?.display_name,
            ].some((value) =>
              value?.toLowerCase().includes(search.toLowerCase()),
            ),
          )
          .map((c) => (
            <ProviderCard
              key={c.id}
              credential={c}
              catalog={catalogByName.get(c.provider_name) ?? null}
              onEdit={onEdit}
              onManageModels={onManageModels}
            />
          ))}
      </div>
    </section>
  );
}
