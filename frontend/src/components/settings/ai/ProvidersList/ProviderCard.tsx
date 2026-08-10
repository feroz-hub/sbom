'use client';

import { useState } from 'react';
import {
  ChevronDown,
  CircleCheck,
  CirclePower,
  Pencil,
  Star,
  Trash2,
} from 'lucide-react';
import {
  useDeleteAiCredential,
  useSetDefaultCredential,
  useSetFallbackCredential,
  useTestConnection,
  useUpdateAiCredential,
} from '@/hooks/useAiCredentials';
import type { AiCredential, AiProviderCatalogEntry } from '@/types/ai';
import { ProviderStatusIndicator } from './ProviderStatusIndicator';
import { ProviderTierBadge } from './ProviderTierBadge';

interface ProviderCardProps {
  credential: AiCredential;
  catalog?: AiProviderCatalogEntry | null;
  onEdit: (credential: AiCredential) => void;
}

/**
 * One row of the providers list.
 *
 * Layout matches Phase 3 §3.1 wireframe: header (provider + role
 * badges + status), middle (model / key / URL preview), trailing
 * actions (Test + kebab menu).
 *
 * Destructive actions confirm before firing — Phase 3 §4.1 hard rule.
 */
export function ProviderCard({ credential, catalog, onEdit }: ProviderCardProps) {
  const setDefault = useSetDefaultCredential();
  const setFallback = useSetFallbackCredential();
  const updateMut = useUpdateAiCredential();
  const deleteMut = useDeleteAiCredential();
  const { saved: testSaved } = useTestConnection();

  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleteText, setDeleteText] = useState('');
  const [menuOpen, setMenuOpen] = useState(false);

  const displayName = catalog?.display_name ?? credential.provider_name;
  const role = credential.is_default
    ? 'default'
    : credential.is_fallback
      ? 'fallback'
      : null;

  return (
    <article
      className="rounded-lg border border-border-subtle bg-surface p-4 shadow-card"
      data-testid={`ai-provider-card-${credential.id}`}
    >
      <header className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <h3 className="flex flex-wrap items-center gap-2 text-sm font-semibold text-hcl-navy">
            {displayName}
            {role ? (
              <span
                className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ${
                  role === 'default'
                    ? 'bg-primary/10 text-primary'
                    : 'bg-cyan-50 text-cyan-800 border border-cyan-200'
                }`}
              >
                <Star className="h-3 w-3" aria-hidden /> {role}
              </span>
            ) : null}
            <ProviderTierBadge tier={credential.tier} catalog={catalog} />
            <ProviderStatusIndicator credential={credential} />
          </h3>
          <p className="mt-1 text-xs text-hcl-muted">
            {credential.default_model ? (
              <>
                <span className="font-medium text-hcl-navy">Model:</span>{' '}
                <span className="font-mono">{credential.default_model}</span>
              </>
            ) : (
              <span className="italic">No default model selected</span>
            )}
          </p>
          {credential.api_key_preview ? (
            <p className="mt-1 text-xs text-hcl-muted">
              <span className="font-medium text-hcl-navy">Key:</span>{' '}
              <span className="font-mono">{credential.api_key_preview}</span>
            </p>
          ) : credential.base_url ? (
            <p className="mt-1 text-xs text-hcl-muted">
              <span className="font-medium text-hcl-navy">URL:</span>{' '}
              <span className="font-mono break-all">{credential.base_url}</span>
            </p>
          ) : null}
        </div>

        <div className="flex shrink-0 items-center gap-2">
          <button
            type="button"
            onClick={() => testSaved.mutate(credential.id)}
            disabled={testSaved.isPending}
            className="inline-flex items-center gap-1 rounded-md border border-border-subtle bg-surface px-2.5 py-1 text-xs font-medium text-hcl-navy hover:bg-surface-muted disabled:cursor-progress disabled:opacity-60"
            aria-label={`Test connection for ${displayName}`}
          >
            <CircleCheck className="h-3.5 w-3.5" aria-hidden />
            {testSaved.isPending ? 'Testing…' : 'Test'}
          </button>

          <div className="relative">
            <button
              type="button"
              onClick={() => setMenuOpen((v) => !v)}
              aria-haspopup="menu"
              aria-expanded={menuOpen}
              className="inline-flex items-center gap-1 rounded-md border border-border-subtle bg-surface px-2 py-1 text-xs text-hcl-navy hover:bg-surface-muted"
            >
              <ChevronDown className="h-3.5 w-3.5" aria-hidden />
            </button>
            {menuOpen ? (
              <ul
                role="menu"
                className="absolute right-0 z-20 mt-1 w-48 rounded-md border border-border-subtle bg-surface shadow-card"
                onMouseLeave={() => setMenuOpen(false)}
              >
                <li>
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => {
                      setMenuOpen(false);
                      onEdit(credential);
                    }}
                    className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-hcl-navy hover:bg-surface-muted"
                  >
                    <Pencil className="h-3.5 w-3.5" aria-hidden /> Edit
                  </button>
                </li>
                <li>
                  <button
                    type="button"
                    role="menuitem"
                    disabled={credential.is_default}
                    onClick={() => {
                      setMenuOpen(false);
                      setDefault.mutate(credential.id);
                    }}
                    className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-hcl-navy hover:bg-surface-muted disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    <Star className="h-3.5 w-3.5" aria-hidden /> Set as default
                  </button>
                </li>
                <li>
                  <button
                    type="button"
                    role="menuitem"
                    disabled={credential.is_fallback}
                    onClick={() => {
                      setMenuOpen(false);
                      setFallback.mutate(credential.id);
                    }}
                    className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-hcl-navy hover:bg-surface-muted disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    <Star className="h-3.5 w-3.5" aria-hidden /> Set as fallback
                  </button>
                </li>
                <li>
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => {
                      setMenuOpen(false);
                      updateMut.mutate({
                        id: credential.id,
                        body: { enabled: !credential.enabled },
                      });
                    }}
                    className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-hcl-navy hover:bg-surface-muted"
                  >
                    <CirclePower className="h-3.5 w-3.5" aria-hidden />
                    {credential.enabled ? 'Disable' : 'Enable'}
                  </button>
                </li>
                <li>
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => {
                      setMenuOpen(false);
                      setConfirmDelete(true);
                    }}
                    className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-red-700 hover:bg-red-50"
                  >
                    <Trash2 className="h-3.5 w-3.5" aria-hidden /> Delete
                  </button>
                </li>
              </ul>
            ) : null}
          </div>
        </div>
      </header>

      {/* Inline test result — appears after a freshly-clicked Test. */}
      {testSaved.data ? (
        <p
          className={`mt-3 text-xs ${
            testSaved.data.success ? 'text-emerald-700' : 'text-red-700'
          }`}
          role="status"
        >
          {testSaved.data.success
            ? `Connected. Latency ${testSaved.data.latency_ms ?? '—'}ms.`
            : `Test failed (${testSaved.data.error_kind ?? 'unknown'}): ${testSaved.data.error_message ?? 'no detail'}`}
        </p>
      ) : null}

      {/* Delete confirmation. Phase 3 §3.4 — type provider name to confirm. */}
      {confirmDelete ? (
        <div className="mt-3 rounded-md border border-red-200 bg-red-50 p-3 text-sm">
          <p className="text-red-800">
            Type <span className="font-mono">{credential.provider_name}</span> to
            confirm deleting this credential.
          </p>
          <input
            value={deleteText}
            onChange={(e) => setDeleteText(e.target.value)}
            className="mt-2 w-full rounded-md border border-border-subtle bg-surface px-2 py-1 text-sm"
            aria-label="Confirm provider name"
          />
          <div className="mt-2 flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={() => {
                setConfirmDelete(false);
                setDeleteText('');
              }}
              className="rounded-md border border-border-subtle bg-surface px-2 py-1 text-xs"
            >
              Cancel
            </button>
            <button
              type="button"
              disabled={deleteText !== credential.provider_name || deleteMut.isPending}
              onClick={() => deleteMut.mutate(credential.id)}
              className="rounded-md bg-red-600 px-2 py-1 text-xs font-medium text-white disabled:cursor-not-allowed disabled:opacity-50"
            >
              {deleteMut.isPending ? 'Deleting…' : 'Delete credential'}
            </button>
          </div>
        </div>
      ) : null}
    </article>
  );
}
