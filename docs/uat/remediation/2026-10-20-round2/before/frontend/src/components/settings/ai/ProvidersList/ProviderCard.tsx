'use client';

import { useState } from 'react';
import {
  ChevronDown,
  CircleCheck,
  CirclePower,
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
import { TestResultDisplay } from '../AddProviderDialog/TestResultDisplay';
import { ProviderStatusIndicator } from './ProviderStatusIndicator';
import { ProviderTierBadge } from './ProviderTierBadge';
import { ConfirmDialog } from '@/components/ui/Dialog';
import { useAiConfigurationScope } from '../ConfigurationScope';

interface ProviderCardProps {
  credential: AiCredential;
  catalog?: AiProviderCatalogEntry | null;
  onEdit: (credential: AiCredential) => void;
  onManageModels: (credential: AiCredential) => void;
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
export function ProviderCard({
  credential,
  catalog,
  onEdit,
  onManageModels,
}: ProviderCardProps) {
  const { canTest, canUpdate = true, scope } = useAiConfigurationScope();
  const setDefault = useSetDefaultCredential();
  const setFallback = useSetFallbackCredential();
  const updateMut = useUpdateAiCredential();
  const deleteMut = useDeleteAiCredential();
  const { saved: testSaved } = useTestConnection();

  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleteText, setDeleteText] = useState('');
  const [menuOpen, setMenuOpen] = useState(false);
  const [confirmDefault, setConfirmDefault] = useState(false);

  const displayName = catalog?.display_name ?? credential.provider_name;
  const role = credential.is_default
    ? 'default'
    : credential.is_fallback
      ? 'fallback'
      : null;

  return (
    <article
      className="rounded-xl border border-border-subtle bg-surface p-4 shadow-card"
      data-testid={`ai-provider-card-${credential.id}`}
    >
      <header className="flex flex-col justify-between gap-4 xl:flex-row xl:items-start">
        <div className="min-w-0 flex-1">
          <h3 className="flex flex-wrap items-center gap-2 text-sm font-semibold text-hcl-navy">
            {displayName}
            {role ? (
              <span
                className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ${
                  role === 'default'
                    ? 'bg-surface-muted text-link border border-border'
                    : 'bg-cyan-50 text-cyan-800 border border-cyan-200 dark:bg-cyan-950 dark:text-cyan-200 dark:border-cyan-800'
                }`}
              >
                <Star className="h-3 w-3" aria-hidden /> {role}
              </span>
            ) : null}
            <ProviderTierBadge tier={credential.tier} catalog={catalog} />
            <ProviderStatusIndicator credential={credential} />
          </h3>
          <p className="mt-2 text-sm text-hcl-muted">
            {credential.provider_name} · {credential.label} ·{' '}
            {credential.enabled ? 'Enabled' : 'Disabled'}
          </p>
          {credential.last_test_at && (
            <p className="mt-1 text-xs text-hcl-muted">
              Last tested:{' '}
              <time
                dateTime={credential.last_test_at}
                title={credential.last_test_at}
              >
                {new Date(credential.last_test_at).toLocaleString()}
              </time>
            </p>
          )}
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
          <p className="mt-2 text-sm text-hcl-muted">
            Credentials:{' '}
            {credential.api_key_present
              ? 'Configured'
              : catalog?.requires_api_key === false
                ? 'Not required'
                : 'Not configured (may not be required)'}
          </p>
          {credential.base_url && (
            <p className="mt-1 break-all font-mono text-xs text-hcl-muted">
              URL: {credential.base_url}
            </p>
          )}
          {credential.rate_per_minute != null && (
            <p className="mt-1 text-xs text-hcl-muted">
              Configured limit: {credential.rate_per_minute.toLocaleString()}{' '}
              requests/min
            </p>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => onManageModels(credential)}
            className="min-h-10 rounded-lg bg-primary px-3 text-sm font-medium text-white"
          >
            Manage models
          </button>
          {canUpdate && (
            <button
              type="button"
              onClick={() => onEdit(credential)}
              className="min-h-10 rounded-lg border border-border px-3 text-sm text-hcl-navy"
            >
              Edit
            </button>
          )}
          <button
            type="button"
            onClick={() => testSaved.mutate(credential.id)}
            disabled={!canTest || testSaved.isPending}
            className="inline-flex min-h-10 items-center gap-1 rounded-md border border-border-subtle bg-surface px-2.5 py-1 text-xs font-medium text-hcl-navy hover:bg-surface-muted disabled:cursor-progress disabled:opacity-60"
            aria-label={`Test connection for ${displayName}`}
          >
            <CircleCheck className="h-3.5 w-3.5" aria-hidden />
            {testSaved.isPending ? 'Testing…' : 'Test connection'}
          </button>

          {canUpdate && (
            <div className="relative">
              <button
                type="button"
                onClick={() => setMenuOpen((v) => !v)}
                aria-label={`More actions for ${displayName}`}
                onKeyDown={(event) => {
                  if (event.key === 'Escape') setMenuOpen(false);
                }}
                aria-expanded={menuOpen}
                className="inline-flex min-h-10 items-center gap-1 rounded-md border border-border-subtle bg-surface px-2 py-1 text-xs text-hcl-navy hover:bg-surface-muted"
              >
                <ChevronDown className="h-3.5 w-3.5" aria-hidden />
              </button>
              {menuOpen ? (
                <ul
                  aria-label="Provider actions"
                  className="absolute right-0 z-20 mt-1 w-48 rounded-md border border-border-subtle bg-surface shadow-card"
                  onKeyDown={(event) => {
                    if (event.key === 'Escape') {
                      setMenuOpen(false);
                      event.currentTarget.parentElement
                        ?.querySelector('button')
                        ?.focus();
                    }
                  }}
                >
                  <li>
                    <button
                      type="button"
                      disabled={credential.is_default || setDefault.isPending}
                      onClick={() => {
                        setMenuOpen(false);
                        setConfirmDefault(true);
                      }}
                      className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-hcl-navy hover:bg-surface-muted disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      <Star className="h-3.5 w-3.5" aria-hidden /> Set as
                      default
                    </button>
                  </li>
                  <li>
                    <button
                      type="button"
                      disabled={credential.is_fallback || setFallback.isPending}
                      onClick={() => {
                        setMenuOpen(false);
                        setFallback.mutate(credential.id);
                      }}
                      className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-hcl-navy hover:bg-surface-muted disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      <Star className="h-3.5 w-3.5" aria-hidden /> Set as
                      fallback
                    </button>
                  </li>
                  <li>
                    <button
                      type="button"
                      disabled={updateMut.isPending}
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
          )}
        </div>
      </header>

      {/* Inline test result — appears after a freshly-clicked Test. */}
      {(testSaved.data || testSaved.error || testSaved.isPending) && (
        <div className="mt-3">
          <TestResultDisplay
            result={testSaved.data ?? null}
            testing={testSaved.isPending}
            error={testSaved.error}
          />
        </div>
      )}

      {[setDefault, setFallback, updateMut, deleteMut].map((mutation, index) =>
        mutation.error ? (
          <p
            key={index}
            role="alert"
            className="mt-3 text-red-700 dark:text-red-300"
          >
            {mutation.error.message}
          </p>
        ) : null,
      )}
      {(setDefault.isPending ||
        setFallback.isPending ||
        updateMut.isPending) && (
        <p role="status" className="mt-3 text-hcl-muted">
          Updating provider…
        </p>
      )}
      {(setDefault.isSuccess ||
        setFallback.isSuccess ||
        updateMut.isSuccess) && (
        <p role="status" className="mt-3 text-hcl-navy">
          Provider updated.
        </p>
      )}
      <ConfirmDialog
        open={confirmDefault}
        onClose={() => {
          if (!setDefault.isPending) setConfirmDefault(false);
        }}
        onConfirm={() =>
          setDefault.mutate(credential.id, {
            onSuccess: () => setConfirmDefault(false),
          })
        }
        title="Change default provider?"
        message={
          (scope === 'platform'
            ? 'This changes the provider used by tenants without an AI configuration override.'
            : 'This changes the default provider for this tenant.') +
          (setDefault.error
            ? ` Unable to change default: ${setDefault.error.message}`
            : '')
        }
        confirmLabel="Set as default"
        variant="primary"
        loading={setDefault.isPending}
      />

      {/* Delete confirmation. Phase 3 §3.4 — type provider name to confirm. */}
      {confirmDelete ? (
        <div className="mt-3 rounded-md border border-red-200 bg-red-50 p-3 text-sm">
          <p className="text-red-800">
            Type <span className="font-mono">{credential.provider_name}</span>{' '}
            to confirm deleting this credential.
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
              disabled={
                deleteText !== credential.provider_name || deleteMut.isPending
              }
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
