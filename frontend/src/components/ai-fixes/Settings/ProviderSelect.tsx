'use client';

import { Check, X } from 'lucide-react';
import type { AiProviderInfo } from '@/types/ai';

interface ProviderSelectProps {
  providers: AiProviderInfo[];
  defaultProvider: string;
}

/**
 * Read-only summary of configured providers + which one is the active
 * default. Editing the default belongs in env / DB — Phase 4 doesn't
 * ship inline editing because secrets in the UI is a correctness risk
 * (Phase 4 §4.3).
 */
export function ProviderSelect({ providers, defaultProvider }: ProviderSelectProps) {
  if (providers.length === 0) {
    return (
      <p className="rounded-lg border border-border-subtle bg-surface p-4 text-sm text-hcl-muted">
        No AI providers configured. Set ``ANTHROPIC_API_KEY`` (or another provider's credentials) in
        the deployment environment.
      </p>
    );
  }

  return (
    <section className="rounded-lg border border-border-subtle bg-surface p-4">
      <h3 className="mb-3 text-sm font-semibold text-hcl-navy">Providers</h3>
      <ul className="space-y-2">
        {providers.map((p) => {
          const isDefault = p.name === defaultProvider;
          return (
            <li
              key={p.name}
              className="flex items-center justify-between gap-3 rounded-md border border-border-subtle bg-surface-muted px-3 py-2"
            >
              <div>
                <p className="text-sm font-medium text-hcl-navy">
                  {p.name}
                  {isDefault ? (
                    <span className="ml-2 rounded-full border border-primary/30 bg-primary/10 px-2 py-0.5 text-xs font-normal text-primary">
                      default
                    </span>
                  ) : null}
                </p>
                <p className="text-xs text-hcl-muted">
                  Model: <span className="font-mono">{p.default_model}</span>
                  {p.is_local ? <> · self-hosted ($0)</> : null}
                </p>
                {p.notes ? <p className="text-xs text-hcl-muted">{p.notes}</p> : null}
              </div>
              <span
                className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ${
                  p.available
                    ? 'border border-emerald-300 bg-emerald-50 text-emerald-800'
                    : 'border border-slate-300 bg-slate-50 text-slate-700'
                }`}
                aria-label={p.available ? 'Available' : 'Unavailable'}
              >
                {p.available ? (
                  <>
                    <Check className="h-3 w-3" aria-hidden /> available
                  </>
                ) : (
                  <>
                    <X className="h-3 w-3" aria-hidden /> unavailable
                  </>
                )}
              </span>
            </li>
          );
        })}
      </ul>
      <p className="mt-3 text-xs text-hcl-muted">
        Default provider is set via the ``AI_DEFAULT_PROVIDER`` environment variable. Credentials are
        sourced from environment / vault — never persisted to the database.
      </p>
    </section>
  );
}
