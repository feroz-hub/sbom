'use client';

import { Plus, Sparkles } from 'lucide-react';
import { useMemo } from 'react';
import { useAiCredentials, useProviderCatalog } from '@/hooks/useAiCredentials';
import type { AiCredential } from '@/types/ai';
import { ProviderCard } from './ProviderCard';

interface ProvidersListProps {
  onAdd: () => void;
  onEdit: (credential: AiCredential) => void;
}

/**
 * Phase 3 §3.1 — the providers list section header + card stack.
 *
 * Shows banner state when no default is set (per §3.8) and an
 * onboarding card when the list is empty.
 */
export function ProvidersList({ onAdd, onEdit }: ProvidersListProps) {
  const { data: credentials, isLoading, isError, error, refetch } = useAiCredentials();
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
      <div className="flex items-center justify-between">
        <h2 id="ai-providers-heading" className="text-base font-semibold text-hcl-navy">
          AI providers
        </h2>
        <button
          type="button"
          onClick={onAdd}
          className="inline-flex items-center gap-1 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-white shadow-elev-1 hover:bg-hcl-dark"
        >
          <Plus className="h-3.5 w-3.5" aria-hidden /> Add provider
        </button>
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
          Could not load providers: {(error as Error)?.message ?? 'unknown error'}.
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
            We recommend Gemini's free tier for evaluation — no credit card required.
          </p>
          <button
            type="button"
            onClick={onAdd}
            className="mt-3 inline-flex items-center gap-1 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-white shadow-elev-1 hover:bg-hcl-dark"
          >
            <Plus className="h-3.5 w-3.5" aria-hidden /> Add provider
          </button>
        </div>
      ) : null}

      {!empty && (credentials ?? []).length > 0 && !hasDefault ? (
        <p
          role="alert"
          className="rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900"
        >
          No default provider selected. AI fixes will fail until you set one.
        </p>
      ) : null}

      <div className="space-y-2">
        {(credentials ?? []).map((c) => (
          <ProviderCard
            key={c.id}
            credential={c}
            catalog={catalogByName.get(c.provider_name) ?? null}
            onEdit={onEdit}
          />
        ))}
      </div>
    </section>
  );
}
