/**
 * React-Query hooks for the Phase 3 credential management UI.
 *
 * Five hooks split by concern:
 *
 *   * ``useAiCredentials``        — CRUD on the saved-credential list
 *   * ``useAiCredentialSettings`` — singleton settings (kill switch + caps)
 *   * ``useTestConnection``       — un-saved + saved test mutations
 *   * ``useProviderCatalog``      — provider fields/bootstrap (Add dialog only)
 *   * ``useRunBatchEstimate``     — free-tier batch-duration warning
 *
 * Mutations always invalidate the relevant query keys so the UI
 * refreshes without manual ``refetch()`` calls. Test-connection
 * mutations are kept ephemeral (no global cache entry) — every click
 * runs a fresh probe, which is the §3.3 contract.
 */

import { useAiConfigurationScope } from '@/components/settings/ai/ConfigurationScope';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  createAiCredential,
  deleteAiCredential,
  getAiCredentialSettings,
  getRunBatchEstimate,
  listAiCredentials,
  listAiProviderCatalog,
  listAiProviderModels,
  refreshAiProviderModels,
  selectAiProviderModel,
  testAiProviderModel,
  setAiCredentialDefault,
  setAiCredentialFallback,
  testAiCredentialSaved,
  testAiCredentialUnsaved,
  updateAiCredential,
  updateAiCredentialSettings,
} from '@/lib/api';
import {
  invalidateAiCredentialSurfaces,
  invalidateAiFixCaches,
} from '@/lib/queryInvalidation';
import type {
  AiBatchDurationEstimate,
  AiConnectionTestResult,
  AiCredential,
  AiCredentialCreateRequest,
  AiCredentialSettings,
  AiCredentialSettingsUpdateRequest,
  AiCredentialUpdateRequest,
  AiProviderCatalogEntry,
  AiProviderModel,
  AiModelRefreshResult,
  AiModelTestResult,
  AiTestConnectionRequest,
} from '@/types/ai';


// ─── Query keys ────────────────────────────────────────────────────────────

export const aiCredentialsQueryKey = ['ai', 'credentials'] as const;
export const aiCredentialSettingsQueryKey = ['ai', 'credential-settings'] as const;
export const aiProviderCatalogQueryKey = ['ai', 'provider-catalog'] as const;
export const aiProviderModelsQueryKey = (credentialId: number) => ['ai', 'provider-models', credentialId] as const;


// ─── Credentials list + mutations ──────────────────────────────────────────


export function useAiCredentials(args: { enabled?: boolean } = {}) {
  const { scope, key } = useAiConfigurationScope();
  return useQuery<AiCredential[]>({
    queryKey: [...aiCredentialsQueryKey, key],
    queryFn: ({ signal }) => listAiCredentials(signal, scope),
    enabled: args.enabled ?? true,
    staleTime: 30_000,
  });
}


export function useCreateAiCredential() {
  const { scope } = useAiConfigurationScope();
  const qc = useQueryClient();
  return useMutation<AiCredential, Error, AiCredentialCreateRequest>({
    mutationFn: (body) => createAiCredential(body, undefined, scope),
    onSuccess: () => {
      invalidateAiCredentialSurfaces(qc);
    },
  });
}


export function useUpdateAiCredential() {
  const { scope } = useAiConfigurationScope();
  const qc = useQueryClient();
  return useMutation<
    AiCredential,
    Error,
    { id: number; body: AiCredentialUpdateRequest }
  >({
    mutationFn: ({ id, body }) => updateAiCredential(id, body, undefined, scope),
    onSuccess: () => {
      invalidateAiCredentialSurfaces(qc);
    },
  });
}


export function useDeleteAiCredential() {
  const { scope } = useAiConfigurationScope();
  const qc = useQueryClient();
  return useMutation<void, Error, number>({
    mutationFn: (id) => deleteAiCredential(id, undefined, scope),
    onSuccess: () => {
      invalidateAiCredentialSurfaces(qc);
      // Cached per-finding fixes reference the deleted provider's name.
      invalidateAiFixCaches(qc);
    },
  });
}


export function useSetDefaultCredential() {
  const { scope } = useAiConfigurationScope();
  const qc = useQueryClient();
  return useMutation<AiCredential, Error, number>({
    mutationFn: (id) => setAiCredentialDefault(id, undefined, scope),
    onSuccess: () => {
      invalidateAiCredentialSurfaces(qc);
    },
  });
}


export function useSetFallbackCredential() {
  const { scope } = useAiConfigurationScope();
  const qc = useQueryClient();
  return useMutation<AiCredential, Error, number>({
    mutationFn: (id) => setAiCredentialFallback(id, undefined, scope),
    onSuccess: () => {
      invalidateAiCredentialSurfaces(qc);
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
  const { scope } = useAiConfigurationScope();
  const qc = useQueryClient();

  // @no-invalidation-needed — probes a candidate config; the saved-credentials
  // list is unchanged by this call.
  const unsaved = useMutation<
    AiConnectionTestResult,
    Error,
    AiTestConnectionRequest
  >({
    mutationFn: (body) => testAiCredentialUnsaved(body, undefined, scope),
  });

  const saved = useMutation<AiConnectionTestResult, Error, number>({
    mutationFn: (id) => testAiCredentialSaved(id, undefined, scope),
    onSuccess: () => {
      // last_test_at / last_test_success on the row just changed — refresh
      // the list so the status badge updates without F5.
      invalidateAiCredentialSurfaces(qc);
    },
  });

  return { unsaved, saved };
}


export function useAiProviderModels(credentialId: number) {
  const { scope, key } = useAiConfigurationScope();
  return useQuery<AiProviderModel[]>({
    queryKey: [...aiProviderModelsQueryKey(credentialId), key],
    queryFn: ({ signal }) => listAiProviderModels(credentialId, signal, scope),
    staleTime: 30_000,
  });
}


export function useRefreshAiProviderModels(credentialId: number) {
  const { scope, key } = useAiConfigurationScope();
  const qc = useQueryClient();
  return useMutation<AiModelRefreshResult, Error>({
    mutationFn: () => refreshAiProviderModels(credentialId, undefined, scope),
    onSuccess: () => qc.invalidateQueries({ queryKey: [...aiProviderModelsQueryKey(credentialId), key] }),
  });
}


export function useSelectAiProviderModel(credentialId: number) {
  const { scope, key } = useAiConfigurationScope();
  const qc = useQueryClient();
  return useMutation<AiProviderModel, Error, number>({
    mutationFn: (modelId) => selectAiProviderModel(credentialId, modelId, undefined, scope),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: [...aiProviderModelsQueryKey(credentialId), key] });
      invalidateAiCredentialSurfaces(qc);
      invalidateAiFixCaches(qc);
    },
  });
}


export function useTestAiProviderModel(credentialId: number) {
  const { scope, key } = useAiConfigurationScope();
  const qc = useQueryClient();
  return useMutation<AiModelTestResult, Error, number>({
    mutationFn: (modelId) => testAiProviderModel(credentialId, modelId, undefined, scope),
    onSuccess: () => qc.invalidateQueries({ queryKey: [...aiProviderModelsQueryKey(credentialId), key] }),
  });
}


// ─── Singleton settings ────────────────────────────────────────────────────


export function useAiCredentialSettings(args: { enabled?: boolean } = {}) {
  const { scope, key } = useAiConfigurationScope();
  return useQuery<AiCredentialSettings>({
    queryKey: [...aiCredentialSettingsQueryKey, key],
    queryFn: ({ signal }) => getAiCredentialSettings(signal, scope),
    enabled: args.enabled ?? true,
    staleTime: 30_000,
  });
}


// Prime the direct settings query, then invalidate every runtime-derived
// surface (analysis config, usage caps, Copilot visibility, fix estimates).
export function useUpdateAiCredentialSettings() {
  const { scope, key } = useAiConfigurationScope();
  const qc = useQueryClient();
  return useMutation<
    AiCredentialSettings,
    Error,
    AiCredentialSettingsUpdateRequest
  >({
    mutationFn: (body) => updateAiCredentialSettings(body, undefined, scope),
    onSuccess: (data) => {
      qc.setQueryData([...aiCredentialSettingsQueryKey, key], data);
      invalidateAiCredentialSurfaces(qc);
      invalidateAiFixCaches(qc);
    },
  });
}


// ─── Provider bootstrap catalog (never the saved model source of truth) ───


export function useProviderCatalog() {
  const { scope, key } = useAiConfigurationScope();
  return useQuery<AiProviderCatalogEntry[]>({
    queryKey: [...aiProviderCatalogQueryKey, key],
    queryFn: ({ signal }) => listAiProviderCatalog(signal, scope),
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
