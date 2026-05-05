/**
 * React-Query hooks for the Phase 3 credential management UI.
 *
 * Five hooks split by concern:
 *
 *   * ``useAiCredentials``        — CRUD on the saved-credential list
 *   * ``useAiCredentialSettings`` — singleton settings (kill switch + caps)
 *   * ``useTestConnection``       — un-saved + saved test mutations
 *   * ``useProviderCatalog``      — static catalog (drives Add dialog form)
 *   * ``useRunBatchEstimate``     — free-tier batch-duration warning
 *
 * Mutations always invalidate the relevant query keys so the UI
 * refreshes without manual ``refetch()`` calls. Test-connection
 * mutations are kept ephemeral (no global cache entry) — every click
 * runs a fresh probe, which is the §3.3 contract.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  createAiCredential,
  deleteAiCredential,
  getAiCredentialSettings,
  getRunBatchEstimate,
  listAiCredentials,
  listAiProviderCatalog,
  setAiCredentialDefault,
  setAiCredentialFallback,
  testAiCredentialSaved,
  testAiCredentialUnsaved,
  updateAiCredential,
  updateAiCredentialSettings,
} from '@/lib/api';
import type {
  AiBatchDurationEstimate,
  AiConnectionTestResult,
  AiCredential,
  AiCredentialCreateRequest,
  AiCredentialSettings,
  AiCredentialSettingsUpdateRequest,
  AiCredentialUpdateRequest,
  AiProviderCatalogEntry,
  AiTestConnectionRequest,
} from '@/types/ai';


// ─── Query keys ────────────────────────────────────────────────────────────

export const aiCredentialsQueryKey = ['ai', 'credentials'] as const;
export const aiCredentialSettingsQueryKey = ['ai', 'credential-settings'] as const;
export const aiProviderCatalogQueryKey = ['ai', 'provider-catalog'] as const;


// ─── Credentials list + mutations ──────────────────────────────────────────


export function useAiCredentials(args: { enabled?: boolean } = {}) {
  return useQuery<AiCredential[]>({
    queryKey: aiCredentialsQueryKey,
    queryFn: ({ signal }) => listAiCredentials(signal),
    enabled: args.enabled ?? true,
    staleTime: 30_000,
  });
}


export function useCreateAiCredential() {
  const qc = useQueryClient();
  return useMutation<AiCredential, Error, AiCredentialCreateRequest>({
    mutationFn: (body) => createAiCredential(body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: aiCredentialsQueryKey });
    },
  });
}


export function useUpdateAiCredential() {
  const qc = useQueryClient();
  return useMutation<
    AiCredential,
    Error,
    { id: number; body: AiCredentialUpdateRequest }
  >({
    mutationFn: ({ id, body }) => updateAiCredential(id, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: aiCredentialsQueryKey });
    },
  });
}


export function useDeleteAiCredential() {
  const qc = useQueryClient();
  return useMutation<void, Error, number>({
    mutationFn: (id) => deleteAiCredential(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: aiCredentialsQueryKey });
    },
  });
}


export function useSetDefaultCredential() {
  const qc = useQueryClient();
  return useMutation<AiCredential, Error, number>({
    mutationFn: (id) => setAiCredentialDefault(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: aiCredentialsQueryKey });
    },
  });
}


export function useSetFallbackCredential() {
  const qc = useQueryClient();
  return useMutation<AiCredential, Error, number>({
    mutationFn: (id) => setAiCredentialFallback(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: aiCredentialsQueryKey });
    },
  });
}


// ─── Test connection (un-saved + saved) ────────────────────────────────────


export interface TestConnectionState {
  result: AiConnectionTestResult | null;
  testing: boolean;
  error: Error | null;
}


/** Hook used inside the Add dialog's "Test connection" button. */
export function useTestConnection() {
  const qc = useQueryClient();

  const unsaved = useMutation<
    AiConnectionTestResult,
    Error,
    AiTestConnectionRequest
  >({
    mutationFn: (body) => testAiCredentialUnsaved(body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: aiCredentialsQueryKey });
    },
  });

  const saved = useMutation<AiConnectionTestResult, Error, number>({
    mutationFn: (id) => testAiCredentialSaved(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: aiCredentialsQueryKey });
    },
  });

  return { unsaved, saved };
}


// ─── Singleton settings ────────────────────────────────────────────────────


export function useAiCredentialSettings(args: { enabled?: boolean } = {}) {
  return useQuery<AiCredentialSettings>({
    queryKey: aiCredentialSettingsQueryKey,
    queryFn: ({ signal }) => getAiCredentialSettings(signal),
    enabled: args.enabled ?? true,
    staleTime: 30_000,
  });
}


export function useUpdateAiCredentialSettings() {
  const qc = useQueryClient();
  return useMutation<
    AiCredentialSettings,
    Error,
    AiCredentialSettingsUpdateRequest
  >({
    mutationFn: (body) => updateAiCredentialSettings(body),
    onSuccess: (data) => {
      qc.setQueryData(aiCredentialSettingsQueryKey, data);
    },
  });
}


// ─── Catalog ───────────────────────────────────────────────────────────────


export function useProviderCatalog() {
  return useQuery<AiProviderCatalogEntry[]>({
    queryKey: aiProviderCatalogQueryKey,
    queryFn: ({ signal }) => listAiProviderCatalog(signal),
    staleTime: 60 * 60_000, // catalog is essentially static within a session
  });
}


// ─── Run batch estimate ────────────────────────────────────────────────────


export function useRunBatchEstimate(
  runId: number | null,
  args: { enabled?: boolean } = {},
) {
  const enabled = (args.enabled ?? true) && runId != null;
  return useQuery<AiBatchDurationEstimate>({
    queryKey: ['ai', 'run-batch-estimate', runId],
    queryFn: ({ signal }) => getRunBatchEstimate(runId as number, signal),
    enabled,
    staleTime: 30_000,
  });
}
