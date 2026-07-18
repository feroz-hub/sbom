import type {
  Project,
  Product,
  ProductListResponse,
  SBOMSource,
  SBOMComponent,
  AnalysisRun,
  AnalysisFinding,
  EnrichedFinding,
  DashboardStats,
  DashboardPosture,
  LifetimeMetrics,
  RecentSbom,
  ActivityData,
  SeverityData,
  SBOMType,
  CreateProjectPayload,
  UpdateProjectPayload,
  CreateSBOMPayload,
  UpdateSBOMPayload,
  AnalyzeSBOMPayload,
  PDFReportPayload,
  ConsolidatedAnalysisResult,
  SBOMInfo,
  SBOMRiskSummary,
  SbomConversionReport,
  SbomConversionResponse,
  ValidationReport,
  DashboardTrend,
  TrendGranularity,
  VulnerabilityAgeResponse,
  AgePeriod,
  CompareRunsResult,
  AnalysisSchedule,
  SbomScheduleResolved,
  ScheduleUpsertPayload,
  DashboardLifecycle,
  DashboardVex,
  LifecycleOverridePayload,
  LifecycleReport,
  VexDiscoveryResponse,
  VexImportResponse,
  VexListResponse,
  VexOverrideHistoryResponse,
  VexOverridePayload,
  AiRepairSuggestion,
  AiFixSuggestionRequest,
  ApplyPatchRequest,
  ValidationRepairEvent,
  ValidationRepairPatch,
  ValidationRepairSession,
  ValidationSessionContentChunk,
  ValidationSessionContentLines,
  ValidationSessionSearchResponse,
  ValidationSessionImportResponse,
  UploadSBOMAcceptedResponse,
  SbomComponentListResponse,
  GetSbomComponentsOptions,
  SbomDocumentStats,
  SbomRawChunk,
  LifecycleProviderConfig,
  LifecycleProviderUpdatePayload,
  LifecycleProviderSecretResult,
  LifecycleProviderTestResult,
  LifecycleProviderSyncResult,
  LifecycleVendorRecord,
  LifecycleVendorRecordPayload,
  LifecycleVendorRecordListResponse,
  LineRepairPatch,
  Fda510kReportExportRequest,
  KevFilterOptions,
  KevListParams,
  KevListResponse,
  KevSyncResult,
  KevVulnerability,
} from '@/types';

// Direct calls to FastAPI — no Next.js proxy (proxy caused ECONNRESET on
// analysis calls that take 47-120s due to Node socket timeout).
//
// NEXT_PUBLIC_API_URL is REQUIRED. There is intentionally no hardcoded
// fallback in source — a silent fallback in production used to send every
// call to a non-existent local backend with no error surfaced to ops.
// The development default is supplied by frontend/.env.development
// (committed) so contributors get a working setup out of the box.
//
// Example: NEXT_PUBLIC_API_URL = "http://api.example.com"
//          request("/api/sboms")  →  http://api.example.com/api/sboms
import { resolveBaseUrl } from './env';
import { getActiveTenantId } from './auth';

export const BASE_URL = process.env.NEXT_PUBLIC_AUTH_ENABLED === 'true'
  ? '/api/backend'
  : resolveBaseUrl();

// ─── Auth header injection ────────────────────────────────────────────────────
// Reads token + active tenant from sessionStorage and returns the headers
// to inject into every outbound API request. This runs on every call so
// the latest token and tenant are always sent (including after refresh or
// tenant switch).
function getAuthHeaders(): Record<string, string> {
  const headers: Record<string, string> = {};
  try {
    const tenantId = getActiveTenantId();
    if (tenantId) {
      headers['X-Tenant-ID'] = tenantId;
    }
  } catch {
    // sessionStorage may not be available in SSR; silently skip
  }
  return headers;
}

// ─── 401/403 response handling ────────────────────────────────────────────────
// On 401: token has expired or been revoked. Clear local tokens and
// redirect to login if auth is enabled. On 403: user lacks permission.
// Redirect to the access-denied page instead of showing a raw error.
let _auth401InFlight = false;

function handleAuthError(status: number, redirectForbidden = true): void {
  if (typeof window === 'undefined') return;

  if (status === 401 && !_auth401InFlight) {
    _auth401InFlight = true;
    const authEnabled = process.env.NEXT_PUBLIC_AUTH_ENABLED === 'true';
    if (authEnabled) {
      // Avoid redirect loops: don't redirect if already on auth pages
      const path = window.location.pathname;
      if (!path.startsWith('/auth/')) {
        // Small delay to batch multiple concurrent 401s into one redirect
        setTimeout(() => {
          const returnTo = `${window.location.pathname}${window.location.search}`;
          window.location.href = `/api/auth/login?returnTo=${encodeURIComponent(returnTo)}`;
          _auth401InFlight = false;
        }, 100);
      } else {
        _auth401InFlight = false;
      }
    } else {
      _auth401InFlight = false;
    }
  }

  if (status === 403 && redirectForbidden) {
    const path = window.location.pathname;
    if (!path.startsWith('/access-denied') && !path.startsWith('/auth/')) {
      window.location.href = '/access-denied';
    }
  }
}

// ─── Typed HTTP error ─────────────────────────────────────────────────────────
export class HttpError extends Error {
  status: number;
  code?: string;
  /**
   * Structured server-side detail payload, when present. The 4xx envelope
   * for sbom validation failures lives here verbatim — see
   * ``SbomValidationFailureDetail`` in @/types. Keeping the raw object
   * around lets the upload modal render the structured rejection card
   * (stage / error count / "View full report" link) without re-fetching.
   */
  detail?: unknown;
  constructor(message: string, status: number, code?: string, detail?: unknown) {
    super(message);
    this.name = 'HttpError';
    this.status = status;
    this.code = code;
    this.detail = detail;
  }
}

export type TenantRole = 'TENANT_ADMIN' | 'SECURITY_ANALYST' | 'DEVELOPER' | 'VIEWER';
export type MembershipStatus = 'ACTIVE' | 'PENDING' | 'DISABLED';

export interface TenantMember {
  membership_id: number;
  user_id: number;
  external_iam_user_id: string;
  email: string | null;
  display_name: string | null;
  user_status: string;
  role: TenantRole;
  status: MembershipStatus;
}

export interface PlatformAdministrator {
  grant_id: number;
  user_id: number;
  external_iam_user_id: string;
  email: string | null;
  display_name: string | null;
  user_status: string;
  role: 'PLATFORM_ADMIN';
  status: 'ACTIVE' | 'DISABLED';
}

// ─── Fetch with timeout + caller-signal support ───────────────────────────────
async function fetchWithTimeout(
  url: string,
  options: RequestInit & { signal?: AbortSignal } = {},
  timeoutMs = 30_000,
): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(
    () => controller.abort(new DOMException('Request timed out after ' + timeoutMs + 'ms', 'TimeoutError')),
    timeoutMs,
  );

  // Forward caller's abort signal so React Query cleanup still works
  const callerSignal = options.signal;
  if (callerSignal) {
    if (callerSignal.aborted) {
      clearTimeout(id);
      controller.abort(callerSignal.reason);
    } else {
      callerSignal.addEventListener('abort', () => {
        clearTimeout(id);
        controller.abort(callerSignal.reason);
      }, { once: true });
    }
  }

  try {
    const { signal: _ignored, ...rest } = options;
    return await fetch(url, { ...rest, signal: controller.signal });
  } finally {
    clearTimeout(id);
  }
}

// ─── Core HTTP helper (parses errors, throws HttpError) ──────────────────────
type ApiRequestOptions = RequestInit & { signal?: AbortSignal; authErrorMode?: 'redirect' | 'throw' };

async function performRequest(
  path: string,
  options: ApiRequestOptions = {},
  timeoutMs = 30_000,
): Promise<Response> {
  const url = `${BASE_URL}${path}`;
  const { authErrorMode = 'redirect', ...fetchOptions } = options;
  const isFormData = typeof FormData !== 'undefined' && fetchOptions.body instanceof FormData;
  const authHeaders = getAuthHeaders();
  const res = await fetchWithTimeout(
    url,
    {
      ...fetchOptions,
      headers: {
        ...(isFormData ? {} : { 'Content-Type': 'application/json' }),
        ...authHeaders,
        ...fetchOptions.headers,
      },
    },
    timeoutMs,
  );

  if (!res.ok) {
    // Handle auth errors before parsing the body
    handleAuthError(res.status, authErrorMode !== 'throw');

    let message = `HTTP ${res.status}: ${res.statusText}`;
    let code: string | undefined;
    let rawDetail: unknown;
    try {
      const body = await res.json();
      if (body?.detail) {
        rawDetail = body.detail;
        if (typeof body.detail === 'string') {
          message = body.detail;
        } else if (typeof body.detail === 'object' && !Array.isArray(body.detail) && body.detail.message) {
          message = body.detail.message;
          // Routers vary: some emit `code`, others (compare, cves) emit
          // `error_code`. Read both so the discriminator survives.
          code = body.detail.error_code ?? body.detail.code;
        } else if (Array.isArray(body.detail)) {
          message = body.detail
            .map((e: { msg?: string; loc?: string[] }) => `${e.loc?.slice(1).join('.')} — ${e.msg}`)
            .join('; ');
        } else {
          message = JSON.stringify(body.detail);
        }
      }
    } catch {
      // ignore JSON parse errors
    }
    throw new HttpError(message, res.status, code, rawDetail);
  }

  return res;
}

// JSON-returning request — for endpoints that return a typed body.
export async function request<T>(
  path: string,
  options: ApiRequestOptions = {},
  timeoutMs = 30_000,
): Promise<T> {
  const res = await performRequest(path, options, timeoutMs);
  // Some endpoints (rare) may legitimately return 204 from a typed function;
  // call sites that expect a body must not call this with a 204-returning route.
  if (res.status === 204) {
    throw new HttpError(
      `Unexpected empty response from ${path} — use requestVoid for endpoints that return 204 No Content.`,
      204,
    );
  }
  return (await res.json()) as T;
}

// Request for endpoints that return a body on 200 but 204 No Content when
// there's nothing to report (e.g. an idle resource). Returns ``null`` on 204
// instead of throwing, so callers can branch on "exists but empty."
async function requestOrNull<T>(
  path: string,
  options: RequestInit & { signal?: AbortSignal } = {},
  timeoutMs = 30_000,
): Promise<T | null> {
  const res = await performRequest(path, options, timeoutMs);
  if (res.status === 204) return null;
  return (await res.json()) as T;
}

// Void request — for endpoints that return no body (DELETE, etc.). No casts.
export async function requestVoid(
  path: string,
  options: ApiRequestOptions = {},
  timeoutMs = 30_000,
): Promise<void> {
  const res = await performRequest(path, options, timeoutMs);
  // Drain the body to free the connection if the server returned one.
  if (res.status !== 204) {
    try {
      await res.text();
    } catch {
      /* ignore */
    }
  }
}

const adminRequestOptions = { authErrorMode: 'throw' as const };

export function getTenantMembers(tenantId: number): Promise<TenantMember[]> {
  return request<TenantMember[]>(`/api/tenants/${tenantId}/users`, adminRequestOptions);
}

export function getAssignableTenantRoles(): Promise<{ roles: TenantRole[] }> {
  return request<{ roles: TenantRole[] }>('/api/tenant-roles', adminRequestOptions);
}

export function addTenantMember(
  tenantId: number,
  payload: { external_user_id: string; role: TenantRole },
): Promise<TenantMember> {
  return request<TenantMember>(`/api/tenants/${tenantId}/users`, {
    ...adminRequestOptions,
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export function updateTenantMemberRole(
  tenantId: number,
  membershipId: number,
  role: TenantRole,
): Promise<TenantMember> {
  return request<TenantMember>(`/api/tenants/${tenantId}/users/${membershipId}`, {
    ...adminRequestOptions,
    method: 'PATCH',
    body: JSON.stringify({ role }),
  });
}

export function activateTenantMember(tenantId: number, membershipId: number): Promise<TenantMember> {
  return request<TenantMember>(`/api/tenants/${tenantId}/users/${membershipId}/activate`, {
    ...adminRequestOptions,
    method: 'POST',
  });
}

export function deactivateTenantMember(tenantId: number, membershipId: number): Promise<TenantMember> {
  return request<TenantMember>(`/api/tenants/${tenantId}/users/${membershipId}/deactivate`, {
    ...adminRequestOptions,
    method: 'POST',
  });
}

export function removeTenantMember(tenantId: number, membershipId: number): Promise<void> {
  return requestVoid(`/api/tenants/${tenantId}/users/${membershipId}`, {
    ...adminRequestOptions,
    method: 'DELETE',
  });
}

export function getPlatformAdministrators(): Promise<PlatformAdministrator[]> {
  return request<PlatformAdministrator[]>('/api/platform/administrators', adminRequestOptions);
}

export function grantPlatformAdministrator(externalUserId: string): Promise<PlatformAdministrator> {
  return request<PlatformAdministrator>('/api/platform/administrators', {
    ...adminRequestOptions,
    method: 'POST',
    body: JSON.stringify({ external_user_id: externalUserId }),
  });
}

export function revokePlatformAdministrator(grantId: number): Promise<void> {
  return requestVoid(`/api/platform/administrators/${grantId}`, {
    ...adminRequestOptions,
    method: 'DELETE',
  });
}

// ─── Analysis config ──────────────────────────────────────────────────────────
export interface AnalysisConfig {
  github_configured: boolean;
  nvd_key_configured: boolean;
  vulndb_configured: boolean;
  max_concurrency: number;
  /**
   * Feature flag for the in-app CVE detail modal. When false, the findings
   * table reverts to the legacy ``<a target="_blank">`` outbound link to
   * GHSA / NVD. Default: true.
   */
  cve_modal_enabled?: boolean;
  /**
   * Master flag for the AI fix generator. When true the per-finding "AI
   * remediation" section and the run-level batch banner render. When
   * false (default), the AI surface is hidden — the rest of the app
   * keeps working unchanged.
   */
  ai_fixes_enabled?: boolean;
  /** Default provider name shown in the empty-state CTA copy. */
  ai_default_provider?: string;
  /**
   * Phase 4 rollout flag — true when the Settings → AI UI surface is
   * enabled. False keeps the route accessible but renders a "feature
   * not enabled" notice instead of the editable surface.
   */
  ai_ui_config_enabled?: boolean;
  [key: string]: unknown;
}

export function getAnalysisConfig(signal?: AbortSignal) {
  return request<AnalysisConfig>('/api/analysis/config', { signal });
}

// ─── Health ──────────────────────────────────────────────────────────────────
// Re-exported for backward-compat with existing call-sites. Canonical type
// now lives in @/types so other modules can consume it without importing
// from @/lib/api (which would pull request infra into pure helpers).
export type { HealthResponse } from '@/types';
import type { HealthResponse } from '@/types';

export function getHealth(signal?: AbortSignal) {
  return request<HealthResponse>('/health', { signal });
}

// ─── Dashboard ───────────────────────────────────────────────────────────────
export function getDashboardStats(signal?: AbortSignal) {
  return request<DashboardStats>('/dashboard/stats', { signal });
}

export function getRecentSboms(limit = 5, signal?: AbortSignal) {
  return request<RecentSbom[]>(`/dashboard/recent-sboms?limit=${limit}`, { signal });
}

export function getDashboardActivity(signal?: AbortSignal) {
  return request<ActivityData>('/dashboard/activity', { signal });
}

export function getDashboardSeverity(signal?: AbortSignal) {
  return request<SeverityData>('/dashboard/severity', { signal });
}

/**
 * ADR-0001 — single source of truth for the home hero. Returns severity
 * counts, KEV count, fix-available count, and freshness so the hero
 * posture state machine can derive the band without joining multiple
 * payloads.
 */
export function getDashboardPosture(signal?: AbortSignal) {
  return request<DashboardPosture>('/dashboard/posture', { signal });
}

export function getDashboardSummary(signal?: AbortSignal) {
  return request<any>('/dashboard/summary', { signal });
}

// ─── Projects ────────────────────────────────────────────────────────────────
export function getProjects(signal?: AbortSignal) {
  return request<Project[]>('/api/projects', { signal });
}

export function getProject(id: number, signal?: AbortSignal) {
  return request<Project>(`/api/projects/${id}`, { signal });
}

export function createProject(payload: CreateProjectPayload, signal?: AbortSignal) {
  return request<Project>('/api/projects', {
    method: 'POST',
    body: JSON.stringify(payload),
    signal,
  });
}

export function getProducts(projectId: number, signal?: AbortSignal) {
  return request<ProductListResponse>(`/api/projects/${projectId}/products`, { signal });
}

export function getProduct(id: number, signal?: AbortSignal) {
  return request<Product>(`/api/products/${id}`, { signal });
}

export function createProduct(projectId: number, payload: Partial<Product> & { name: string }, signal?: AbortSignal) {
  return request<Product>(`/api/projects/${projectId}/products`, {
    method: 'POST',
    body: JSON.stringify(payload),
    signal,
  });
}

export function updateProduct(id: number, payload: Partial<Product>, signal?: AbortSignal) {
  return request<Product>(`/api/products/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
    signal,
  });
}

export function deleteProduct(id: number, signal?: AbortSignal) {
  return request<{ status: string; product_id: number }>(`/api/products/${id}`, {
    method: 'DELETE',
    signal,
  });
}

export function getProductSboms(id: number, signal?: AbortSignal) {
  return request<SBOMSource[]>(`/api/products/${id}/sboms`, { signal });
}

export function updateProject(
  id: number,
  payload: UpdateProjectPayload,
  signal?: AbortSignal
) {
  return request<Project>(`/api/projects/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
    signal,
  });
}

export interface ProjectDeleteImpact {
  project_id: number;
  project_name: string;
  sboms: number;
  components: number;
  runs: number;
  findings: number;
  schedules: number;
}

export function getProjectDeleteImpact(id: number, signal?: AbortSignal) {
  return request<ProjectDeleteImpact>(`/api/projects/${id}/delete-impact`, { signal });
}

export function deleteProject(
  id: number,
  options: { permanent?: boolean; userId?: string } = {},
  signal?: AbortSignal,
) {
  const params = new URLSearchParams({ confirm: 'yes' });
  if (options.permanent) params.set('permanent', 'true');
  if (options.userId) params.set('user_id', options.userId);
  return requestVoid(`/api/projects/${id}?${params.toString()}`, {
    method: 'DELETE',
    signal,
  });
}

// ─── SBOMs ───────────────────────────────────────────────────────────────────
export function getSboms(page = 1, pageSize = 50, signal?: AbortSignal) {
  return request<SBOMSource[]>(`/api/sboms?page=${page}&page_size=${pageSize}`, { signal });
}

export function getSbom(id: number, signal?: AbortSignal, includeRaw = false) {
  const qs = includeRaw ? '?include_raw=true' : '';
  return request<SBOMSource>(`/api/sboms/${id}${qs}`, { signal });
}

export function getSbomStats(sbomId: number, signal?: AbortSignal) {
  return request<SbomDocumentStats>(`/api/sboms/${sbomId}/stats`, { signal });
}

export function getSbomRawChunk(
  sbomId: number,
  offset = 0,
  limit = 500,
  signal?: AbortSignal,
) {
  return request<SbomRawChunk>(
    `/api/sboms/${sbomId}/raw?offset=${offset}&limit=${limit}`,
    { signal },
  );
}

export async function downloadSbomOriginal(sbomId: number, signal?: AbortSignal): Promise<Blob> {
  const res = await performRequest(`/api/sboms/${sbomId}/download`, { signal }, 120_000);
  return res.blob();
}

export function createSbom(payload: CreateSBOMPayload, signal?: AbortSignal) {
  return request<SBOMSource>('/api/sboms', {
    method: 'POST',
    body: JSON.stringify(payload),
    signal,
  });
}

export async function uploadSbom(payload: CreateSBOMPayload, signal?: AbortSignal) {
  const form = new FormData();
  if (payload.sbom_file) {
    form.set('file', payload.sbom_file, payload.sbom_file.name);
  } else {
    const filename = `${payload.sbom_name || 'sbom'}.${payload.sbom_data.trimStart().startsWith('<') ? 'xml' : 'json'}`;
    form.set('file', new Blob([payload.sbom_data], { type: 'application/octet-stream' }), filename);
  }
  form.set('sbom_name', payload.sbom_name);
  const projectId = payload.project_id ?? payload.projectid;
  if (projectId != null) form.set('project_id', String(projectId));
  if (payload.product_id != null) form.set('product_id', String(payload.product_id));
  if (payload.sbom_type != null) form.set('sbom_type', String(payload.sbom_type));
  if (payload.sbom_version) form.set('sbom_version', payload.sbom_version);
  const productVersion = payload.product_version ?? payload.productver;
  if (productVersion) form.set('product_version', productVersion);
  if (payload.created_by) form.set('created_by', payload.created_by);

  const accepted = await request<UploadSBOMAcceptedResponse>(
    '/api/sboms/upload',
    {
      method: 'POST',
      body: form,
      signal,
    },
    120_000,
  );
  const sbom = await getSbom(accepted.sbom_id, signal);
  return {
    ...sbom,
    upload_status: accepted.status,
    validation_status: accepted.status,
    product_id: accepted.product_id ?? sbom.product_id,
    product_name: accepted.product_name ?? sbom.product_name,
    workspace_id: accepted.workspace_id,
    validation_session_id: accepted.validation_session_id,
    repair_workspace_url: accepted.repair_workspace_url,
    detected_format: accepted.detected_format ?? accepted.spec,
    detected_spec_version: accepted.detected_spec_version ?? accepted.spec_version,
    detection_confidence: accepted.detection_confidence,
    file_size_bytes: accepted.file_size_bytes,
    total_lines: accepted.total_lines,
    sha256: accepted.sha256,
    is_large_file: accepted.is_large_file,
    full_editor_allowed: accepted.full_editor_allowed,
    validation_errors: accepted.validation_errors ?? [],
    warning_count: accepted.validation_warnings?.length ?? accepted.warnings?.length ?? sbom.warning_count,
  };
}

export function updateSbom(
  id: number,
  payload: UpdateSBOMPayload,
  signal?: AbortSignal
) {
  return request<SBOMSource>(`/api/sboms/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
    signal,
  });
}

export function editSbom(id: number, payload: any, userId?: string, signal?: AbortSignal) {
  const qs = userId ? `?user_id=${encodeURIComponent(userId)}` : '';
  return request<SBOMSource>(`/api/sboms/${id}/edit${qs}`, {
    method: 'POST',
    body: JSON.stringify(payload),
    signal,
  });
}

export function createWorkspaceForSbom(sbomId: number, signal?: AbortSignal) {
  return request<ValidationRepairSession>(`/api/sboms/${sbomId}/workspace`, {
    method: 'POST',
    signal,
  });
}

export function getSbomVersions(id: number, signal?: AbortSignal) {
  return request<SBOMSource[]>(`/api/sboms/${id}/versions`, { signal });
}

export function compareSbomVersions(versionA: number, versionB: number, signal?: AbortSignal) {
  return request<{
    added: any[];
    removed: any[];
    changed: any[];
  }>(`/api/sboms/compare-versions?version_a=${versionA}&version_b=${versionB}`, { signal });
}

export function restoreSbomVersion(id: number, versionId: number, userId?: string, signal?: AbortSignal) {
  const qs = userId ? `?user_id=${encodeURIComponent(userId)}` : '';
  return request<SBOMSource>(`/api/sboms/${id}/restore/${versionId}${qs}`, {
    method: 'POST',
    signal,
  });
}

export interface SbomDeleteImpact {
  sbom_id: number;
  sbom_name: string;
  components: number;
  runs: number;
  findings: number;
  can_delete: boolean;
  requires_confirmation: boolean;
  dependent_counts: {
    components: number;
    analysis_runs: number;
    vulnerabilities: number;
    remediations: number;
    validation_reports: number;
    validation_sessions: number;
    validation_events: number;
    vex_documents: number;
    vex_statements: number;
    schedules: number;
    versions: number;
    derived_sboms: number;
    lifecycle_override_audits: number;
    vex_override_audits: number;
    ai_fix_batches: number;
    run_cache_rows: number;
    compare_cache_rows: number;
  };
  table_counts: Record<string, number>;
  blocking_dependencies: Record<string, number>;
  child_sbom_ids: number[];
  child_sboms: Array<{
    sbom_id: number;
    sbom_name: string;
    parent_id: number | null;
    source_sbom_id: number | null;
    converted_sbom_id: number | null;
  }>;
  warnings: string[];
  delete_order: string[];
}

export function getSbomDeleteImpact(id: number, signal?: AbortSignal) {
  return request<SbomDeleteImpact>(`/api/sboms/${id}/delete-impact`, { signal });
}

export function deleteSbom(
  id: number,
  userId: number | string,
  options: { permanent?: boolean } = {},
  signal?: AbortSignal,
) {
  const params = new URLSearchParams({
    user_id: String(userId),
    confirm: 'yes',
  });
  if (options.permanent) params.set('permanent', 'true');
  return requestVoid(`/api/sboms/${id}?${params.toString()}`, {
    method: 'DELETE',
    signal,
  });
}

export function getSbomComponents(
  sbomId: number,
  options: GetSbomComponentsOptions = {},
): Promise<SbomComponentListResponse> {
  const {
    includeDuplicates = false,
    page = 1,
    pageSize = 100,
    search,
    sortBy = 'name',
    sortOrder = 'asc',
    signal,
  } = options;
  const params = new URLSearchParams({
    include_duplicates: includeDuplicates ? 'true' : 'false',
    page: String(page),
    page_size: String(pageSize),
    sort_by: sortBy,
    sort_order: sortOrder,
  });
  if (search?.trim()) {
    params.set('search', search.trim());
  }
  return request<SbomComponentListResponse>(`/api/sboms/${sbomId}/components?${params.toString()}`, {
    signal,
  });
}

export function getSbomDedupeReport(sbomId: number, signal?: AbortSignal) {
  return request<any>(`/api/sboms/${sbomId}/dedupe-report`, { signal });
}

export function getSbomNormalizationReport(sbomId: number, signal?: AbortSignal) {
  return request<any>(`/api/sboms/${sbomId}/normalization-report`, { signal });
}

export function normalizeDeduplicateSbom(sbomId: number, force = true, signal?: AbortSignal) {
  return request<any>(`/api/sboms/${sbomId}/normalize-deduplicate?force=${force ? 'true' : 'false'}`, {
    method: 'POST',
    signal,
  });
}

export function refreshSbomLifecycle(sbomId: number, force = true, signal?: AbortSignal) {
  return request<import('@/types').LifecycleRefreshSummary>(
    `/api/sboms/${sbomId}/lifecycle/refresh?force=${force ? 'true' : 'false'}`,
    {
      method: 'POST',
      signal,
    },
    120_000,
  );
}

export function getLifecycleProviderStatus(signal?: AbortSignal) {
  return request<import('@/types').LifecycleProviderStatus>('/api/lifecycle/provider-status', { signal });
}

export function getLifecycleSources(signal?: AbortSignal) {
  return request<{ sources: import('@/types').LifecycleProviderSource[] }>('/api/lifecycle/sources', { signal });
}

export function getSbomLifecycleReport(sbomId: number, signal?: AbortSignal) {
  return request<LifecycleReport>(`/api/sboms/${sbomId}/lifecycle/report`, { signal });
}

export function exportSbomLifecycleReportCsv(sbomId: number, reportType = 'all', signal?: AbortSignal) {
  const params = new URLSearchParams({ format: 'csv' });
  if (reportType && reportType !== 'all') params.set('report_type', reportType);
  return downloadBinary(
    `/api/sboms/${sbomId}/lifecycle/report?${params.toString()}`,
    `sbom_${sbomId}_lifecycle${reportType && reportType !== 'all' ? `_${reportType}` : ''}.csv`,
    signal,
  );
}

export function exportSbomLifecycleReportPack(sbomId: number, signal?: AbortSignal) {
  return downloadBinary(`/api/sboms/${sbomId}/reports/lifecycle-pack`, `sbom_${sbomId}_lifecycle_reports.zip`, signal);
}

export function refreshComponentLifecycle(componentId: number, force = true, signal?: AbortSignal) {
  return request<SBOMComponent>(
    `/api/components/${componentId}/lifecycle/refresh?force=${force ? 'true' : 'false'}`,
    {
      method: 'POST',
      signal,
    },
    120_000,
  );
}

export function overrideComponentLifecycle(
  componentId: number,
  payload: LifecycleOverridePayload,
  signal?: AbortSignal,
) {
  return request<SBOMComponent>(
    `/api/components/${componentId}/lifecycle-override`,
    {
      method: 'PATCH',
      body: JSON.stringify(payload),
      signal,
    },
    2000,
  );
}

export function analyzeSbom(sbomId: number, signal?: AbortSignal) {
  return request<AnalysisRun>(`/api/sboms/${sbomId}/analyze`, {
    method: 'POST',
    signal,
  }, 180_000);  // analysis can take up to 120s
}

// ─── Consolidated Analysis ───────────────────────────────────────────────────
export function analyzeConsolidated(payload: AnalyzeSBOMPayload, signal?: AbortSignal) {
  return request<ConsolidatedAnalysisResult>('/analyze-sbom-consolidated', {
    method: 'POST',
    body: JSON.stringify(payload),
    signal,
  }, 180_000);  // 180s — NVD alone can take 60s+
}

// ─── Analysis Runs ────────────────────────────────────────────────────────────
export interface RunsFilter {
  sbom_id?: number;
  project_id?: number;
  product_id?: number;
  run_status?: string;
  page?: number;
  page_size?: number;
}

/**
 * Build query params for /api/runs. Positive-integer filters that are NaN,
 * zero, negative, or non-finite are silently dropped — sending them would
 * cause a 422 from the FastAPI validator. This used to happen when a stale
 * select value was passed through `Number()`.
 */
function buildRunsQuery(filter: RunsFilter): URLSearchParams {
  const params = new URLSearchParams();
  const addPositiveInt = (key: string, value: number | undefined) => {
    if (value === undefined) return;
    if (!Number.isFinite(value)) return; // drops NaN and ±Infinity
    if (value <= 0) return;               // backend requires ge=1 on these
    params.set(key, String(Math.trunc(value)));
  };
  addPositiveInt('sbom_id', filter.sbom_id);
  addPositiveInt('project_id', filter.project_id);
  addPositiveInt('product_id', filter.product_id);
  if (filter.run_status && filter.run_status.trim() !== '') {
    params.set('run_status', filter.run_status.trim());
  }
  addPositiveInt('page', filter.page ?? 1);
  addPositiveInt('page_size', filter.page_size ?? 50);
  return params;
}

export function getRuns(filter: RunsFilter = {}, signal?: AbortSignal) {
  const params = buildRunsQuery(filter);
  return request<AnalysisRun[]>(`/api/runs?${params.toString()}`, { signal });
}

// ─── Analysis Runs aggregate (server-side tile values) ───────────────────────
// Mirrors RunsAggregateOut in app/schemas.py. Fixes audit §I0.4-F1
// (legacy PASS/FAIL filters) and §I0.4-F2 (page-slice undercount).
export interface RunsAggregate {
  total_runs: number;
  by_outcome: {
    no_issues: number;
    with_findings: number;
    source_errors: number;
    failed: number;
    other: number;
  };
  total_findings: number;
}

export function getRunsAggregate(
  filter: { sbom_id?: number; project_id?: number } = {},
  signal?: AbortSignal,
) {
  const params = new URLSearchParams();
  if (filter.sbom_id !== undefined && Number.isFinite(filter.sbom_id) && filter.sbom_id > 0) {
    params.set('sbom_id', String(Math.trunc(filter.sbom_id)));
  }
  if (
    filter.project_id !== undefined &&
    Number.isFinite(filter.project_id) &&
    filter.project_id > 0
  ) {
    params.set('project_id', String(Math.trunc(filter.project_id)));
  }
  const qs = params.toString();
  return request<RunsAggregate>(
    qs ? `/api/runs/aggregate?${qs}` : `/api/runs/aggregate`,
    { signal },
  );
}

export function getRun(id: number, signal?: AbortSignal) {
  return request<AnalysisRun>(`/api/runs/${id}`, { signal });
}

export function getRunFindings(
  id: number,
  opts: { severity?: string; page?: number; page_size?: number } = {},
  signal?: AbortSignal
) {
  const params = new URLSearchParams();
  if (opts.severity) params.set('severity', opts.severity);
  params.set('page', String(opts.page ?? 1));
  params.set('page_size', String(opts.page_size ?? 100));
  return request<AnalysisFinding[]>(`/api/runs/${id}/findings?${params.toString()}`, { signal });
}

/** Backend caps page_size at 1000; reads ``X-Total-Count`` and follows pages until all rows are loaded. */
const RUN_FINDINGS_PAGE_SIZE = 1000;
const RUN_FINDINGS_MAX_PAGES = 500;

/**
 * Enriched findings — same shape as `getRunFindings` plus per-finding KEV
 * flag, EPSS score/percentile, and the composite risk score from the v2
 * scorer (`cvss * (1 + 5*epss) * (kev ? 2 : 1)`).
 *
 * Hits POST-warmed KEV/EPSS caches on the backend, so subsequent calls for
 * the same CVEs are served in-memory.
 */
export function getEnrichedRunFindings(
  id: number,
  opts: { severity?: string; page?: number; page_size?: number } = {},
  signal?: AbortSignal,
) {
  const params = new URLSearchParams();
  if (opts.severity) params.set('severity', opts.severity);
  params.set('page', String(opts.page ?? 1));
  params.set('page_size', String(opts.page_size ?? 100));
  return request<EnrichedFinding[]>(
    `/api/runs/${id}/findings-enriched?${params.toString()}`,
    { signal },
  );
}

/** Paginate every enriched finding for a run, mirroring `getAllRunFindings`. */
export async function getAllEnrichedRunFindings(
  id: number,
  opts: { severity?: string } = {},
  signal?: AbortSignal,
): Promise<{ findings: EnrichedFinding[]; totalCount: number }> {
  const all: EnrichedFinding[] = [];
  let totalCount = 0;

  for (let page = 1; page <= RUN_FINDINGS_MAX_PAGES; page++) {
    const params = new URLSearchParams();
    if (opts.severity) params.set('severity', opts.severity);
    params.set('page', String(page));
    params.set('page_size', String(RUN_FINDINGS_PAGE_SIZE));

    const res = await performRequest(
      `/api/runs/${id}/findings-enriched?${params.toString()}`,
      { signal },
    );
    const hdr = res.headers.get('X-Total-Count');
    const parsed = hdr != null && hdr !== '' ? Number.parseInt(hdr, 10) : NaN;
    if (Number.isFinite(parsed)) {
      totalCount = parsed;
    }

    const batch = (await res.json()) as EnrichedFinding[];
    all.push(...batch);

    if (batch.length === 0) break;
    if (totalCount > 0 && all.length >= totalCount) break;
    if (batch.length < RUN_FINDINGS_PAGE_SIZE) break;
  }

  if (totalCount <= 0) {
    totalCount = all.length;
  }

  return { findings: all, totalCount };
}

export async function getAllRunFindings(
  id: number,
  opts: { severity?: string } = {},
  signal?: AbortSignal,
): Promise<{ findings: AnalysisFinding[]; totalCount: number }> {
  const all: AnalysisFinding[] = [];
  let totalCount = 0;

  for (let page = 1; page <= RUN_FINDINGS_MAX_PAGES; page++) {
    const params = new URLSearchParams();
    if (opts.severity) params.set('severity', opts.severity);
    params.set('page', String(page));
    params.set('page_size', String(RUN_FINDINGS_PAGE_SIZE));

    const res = await performRequest(`/api/runs/${id}/findings?${params.toString()}`, { signal });
    const hdr = res.headers.get('X-Total-Count');
    const parsed = hdr != null && hdr !== '' ? Number.parseInt(hdr, 10) : NaN;
    if (Number.isFinite(parsed)) {
      totalCount = parsed;
    }

    const batch = (await res.json()) as AnalysisFinding[];
    all.push(...batch);

    if (batch.length === 0) break;
    if (totalCount > 0 && all.length >= totalCount) break;
    if (batch.length < RUN_FINDINGS_PAGE_SIZE) break;
  }

  if (totalCount <= 0) {
    totalCount = all.length;
  }

  return { findings: all, totalCount };
}

/**
 * Download the current filtered runs list as a JSON file. Aggregates across
 * pages (up to `maxRuns`) so filters like "all runs" don't silently cap at
 * page_size. Uses the same safe param builder as `getRuns`, so invalid
 * filter values can never produce a 422 that would leave the user with a
 * silently-empty download.
 *
 * The backend's `/api/runs` endpoint is capped at `page_size=500`, so we
 * paginate explicitly and stitch the pages together client-side.
 */
export async function exportRunsJson(
  filter: RunsFilter = {},
  opts: { maxRuns?: number } = {},
): Promise<void> {
  const maxRuns = opts.maxRuns ?? 5000;
  const pageSize = 500; // backend hard cap
  const all: AnalysisRun[] = [];

  for (let page = 1; all.length < maxRuns; page++) {
    const params = buildRunsQuery({ ...filter, page, page_size: pageSize });
    const batch = await request<AnalysisRun[]>(`/api/runs?${params.toString()}`);
    if (batch.length === 0) break;
    all.push(...batch);
    if (batch.length < pageSize) break; // last page
  }

  if (all.length === 0) {
    throw new HttpError('No analysis runs match the current filters.', 404);
  }

  const payload = {
    exported_at: new Date().toISOString(),
    filter,
    count: all.length,
    runs: all,
  };

  const blob = new Blob([JSON.stringify(payload, null, 2)], {
    type: 'application/json',
  });
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const filename = `analysis_runs_${timestamp}.json`;

  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.rel = 'noopener';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  } finally {
    // Revoke asynchronously so Safari/Firefox have time to start the download
    // before the blob URL is invalidated.
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}

// ─── PDF Report ───────────────────────────────────────────────────────────────
// PDF generation reads every finding for the run from the DB and renders with
// reportlab; for runs with thousands of findings this can exceed 60s, so we
// allow up to 180s in line with other long-running endpoints.
export async function downloadPdfReport(
  payload: PDFReportPayload,
  signal?: AbortSignal,
): Promise<Blob> {
  const res = await performRequest(
    '/api/pdf-report',
    {
      method: 'POST',
      body: JSON.stringify(payload),
      signal,
    },
    180_000,
  );
  return res.blob();
}

// ─── SBOM Types ───────────────────────────────────────────────────────────────
export function getSbomTypes(signal?: AbortSignal) {
  return request<SBOMType[]>('/api/types', { signal });
}

// ─── SBOM info / risk-summary ────────────────────────────────────────────────
export function getSbomInfo(sbomId: number, signal?: AbortSignal) {
  return request<SBOMInfo>(`/api/sboms/${sbomId}/info`, { signal });
}

export function getSbomRiskSummary(sbomId: number, signal?: AbortSignal) {
  return request<SBOMRiskSummary>(`/api/sboms/${sbomId}/risk-summary`, { signal });
}

export function getSbomValidationReport(sbomId: number, signal?: AbortSignal) {
  return request<ValidationReport>(`/api/sboms/${sbomId}/validation-report`, { signal });
}

export function convertSbomToCycloneDX(sbomId: number, userId?: string, signal?: AbortSignal) {
  const params = userId ? `?user_id=${encodeURIComponent(userId)}` : '';
  return request<SbomConversionResponse>(`/api/sboms/${sbomId}/convert/cyclonedx${params}`, {
    method: 'POST',
    signal,
  });
}

export function getSbomConversionReport(sbomId: number, signal?: AbortSignal) {
  return request<SbomConversionReport>(`/api/sboms/${sbomId}/conversion-report`, { signal });
}

export function exportSbomDocument(
  sbomId: number,
  opts?: { format?: string; exportMode?: string },
  signal?: AbortSignal,
) {
  const params = new URLSearchParams();
  if (opts?.format) params.set('format', opts.format);
  if (opts?.exportMode) params.set('export_mode', opts.exportMode);
  const qs = params.toString();
  const suffix = qs ? `?${qs}` : '';
  return downloadBinary(`/api/sboms/${sbomId}/export${suffix}`, `sbom_${sbomId}.json`, signal);
}

export function exportSbomVulnerabilityExcel(sbomId: number, signal?: AbortSignal) {
  return downloadBinary(
    `/api/sboms/${sbomId}/reports/vulnerabilities.xlsx`,
    `sbom-${sbomId}-vulnerability-report.xlsx`,
    signal,
  );
}

export function exportFda510kSbomReport(
  projectId: number,
  payload: Fda510kReportExportRequest,
  signal?: AbortSignal,
) {
  return downloadBinary(
    `/api/projects/${projectId}/reports/fda-510k-sbom/export`,
    `project-${projectId}-FDA-510k-SBOM-Report.xlsx`,
    signal,
    {
      method: 'POST',
      body: JSON.stringify(payload),
    },
  );
}

/**
 * Re-run the 8-stage validator against the stored SBOM body and persist
 * the outcome on the row. Used by the "Run validation" affordance on
 * legacy ``status === 'pending'`` rows. The response body matches the
 * upload endpoint: 200 + ``SBOMSource`` on a clean report, 4xx with
 * ``HttpError.detail`` carrying the structured failure when the report
 * has any error-severity entry.
 */
export function revalidateSbom(sbomId: number, signal?: AbortSignal) {
  return request<SBOMSource>(`/api/sboms/${sbomId}/revalidate`, {
    method: 'POST',
    signal,
  });
}

export function getValidationSession(sessionId: string, signal?: AbortSignal) {
  return request<ValidationRepairSession>(`/api/sbom-validation-sessions/${sessionId}`, { signal });
}

export function getValidationSessionContent(
  sessionId: string,
  offset = 0,
  limit = 65_536,
  signal?: AbortSignal,
  source: 'original' | 'repair_draft' | 'repair' = 'repair_draft',
) {
  const params = new URLSearchParams({ offset: String(offset), limit: String(limit), source });
  return request<ValidationSessionContentChunk>(
    `/api/sbom-validation-sessions/${sessionId}/content?${params.toString()}`,
    { signal },
  );
}

export function getValidationSessionContentLines(
  sessionId: string,
  startLine = 1,
  lineCount = 500,
  signal?: AbortSignal,
  source: 'original' | 'repair_draft' | 'repair' = 'repair_draft',
) {
  const params = new URLSearchParams({ start_line: String(startLine), line_count: String(lineCount), source });
  return request<ValidationSessionContentLines>(
    `/api/sbom-validation-sessions/${sessionId}/content-lines?${params.toString()}`,
    { signal },
  );
}

export function searchValidationSession(
  sessionId: string,
  query: string,
  source: 'original' | 'repair_draft' | 'repair' = 'repair_draft',
  limit = 100,
  signal?: AbortSignal,
) {
  const params = new URLSearchParams({ q: query, source, limit: String(limit) });
  return request<ValidationSessionSearchResponse>(
    `/api/sbom-validation-sessions/${sessionId}/search?${params.toString()}`,
    { signal },
  );
}

export function downloadValidationSessionOriginal(sessionId: string, signal?: AbortSignal) {
  return downloadBinary(
    `/api/sbom-validation-sessions/${sessionId}/download-original`,
    `invalid-sbom-${sessionId}.txt`,
    signal,
  );
}

export function downloadValidationSessionRepairDraft(sessionId: string, signal?: AbortSignal) {
  return downloadBinary(
    `/api/sbom-validation-sessions/${sessionId}/download-repair-draft`,
    `repair-draft-${sessionId}.txt`,
    signal,
  );
}

export function saveValidationSessionRepairDraft(
  sessionId: string,
  content: string,
  baseVersion?: string | null,
  signal?: AbortSignal,
) {
  return request<ValidationRepairSession>(`/api/sbom-validation-sessions/${sessionId}/repair-draft`, {
    method: 'PUT',
    body: JSON.stringify({ content, base_version: baseVersion ?? null }),
    signal,
  });
}

export function updateValidationSession(
  sessionId: string,
  content: string | null | { current_content?: string | null; project_id?: number | null },
  signal?: AbortSignal,
) {
  const body = typeof content === 'string' || content === null
    ? { current_content: content }
    : content;
  return request<ValidationRepairSession>(`/api/sbom-validation-sessions/${sessionId}`, {
    method: 'PATCH',
    body: JSON.stringify(body),
    signal,
  });
}

export function validateValidationSession(sessionId: string, signal?: AbortSignal) {
  return request<ValidationRepairSession>(`/api/sbom-validation-sessions/${sessionId}/revalidate`, {
    method: 'POST',
    signal,
  });
}

export function importValidationSession(sessionId: string, projectRequired = false, signal?: AbortSignal) {
  const qs = projectRequired ? '?project_required=true' : '';
  return request<ValidationSessionImportResponse>(`/api/sbom-validation-sessions/${sessionId}/import${qs}`, {
    method: 'POST',
    signal,
  });
}

export function suggestValidationSessionFixes(
  sessionId: string,
  payload: AiFixSuggestionRequest = {},
  signal?: AbortSignal,
) {
  return request<AiRepairSuggestion>(
    `/api/sbom-validation-sessions/${sessionId}/ai/suggest-fixes`,
    {
      method: 'POST',
      body: JSON.stringify({ user_instruction: payload.user_instruction ?? '' }),
      signal,
    },
    120_000,
  );
}

export function applyValidationSessionPatch(
  sessionId: string,
  patchPayload: ApplyPatchRequest,
  signal?: AbortSignal,
) {
  return request<ValidationRepairSession>(`/api/sbom-validation-sessions/${sessionId}/apply-patch`, {
    method: 'POST',
    body: JSON.stringify(patchPayload),
    signal,
  });
}

export function applyValidationSessionLinePatches(
  sessionId: string,
  patches: LineRepairPatch[],
  signal?: AbortSignal,
) {
  return request<ValidationRepairSession>(`/api/sbom-validation-sessions/${sessionId}/repair/patches`, {
    method: 'POST',
    body: JSON.stringify({ patches }),
    signal,
  });
}

export function getValidationSessionHistory(sessionId: string, signal?: AbortSignal) {
  return request<ValidationRepairEvent[]>(`/api/sbom-validation-sessions/${sessionId}/history`, { signal });
}

export const getValidationRepairSession = getValidationSession;
export const getValidationRepairContent = getValidationSessionContent;
export const saveValidationRepairDraft = saveValidationSessionRepairDraft;
export const updateValidationRepairSession = updateValidationSession;
export const validateRepairSession = validateValidationSession;
export const importRepairSession = importValidationSession;
export function suggestValidationRepairFixes(
  sessionId: string,
  userInstruction?: string,
  signal?: AbortSignal,
) {
  return suggestValidationSessionFixes(sessionId, { user_instruction: userInstruction ?? '' }, signal);
}
export function applyValidationRepairPatch(
  sessionId: string,
  patches: ValidationRepairPatch[],
  signal?: AbortSignal,
) {
  return applyValidationSessionPatch(sessionId, { patches }, signal);
}
export const getValidationRepairHistory = getValidationSessionHistory;

// ─── Dashboard trend ─────────────────────────────────────────────────────────
export function getDashboardTrend(days = 30, signal?: AbortSignal) {
  return request<DashboardTrend>(`/dashboard/trend?days=${days}`, { signal });
}

/**
 * Manager trend: period-bucketed (granularity) + optional application filter,
 * with fix_available / resolved overlays on each point. Distinct from the
 * legacy daily `getDashboardTrend` so the existing chart is untouched.
 */
export function getDashboardTrendFiltered(
  opts: { granularity: TrendGranularity; applicationIds?: number[] },
  signal?: AbortSignal,
) {
  const params = new URLSearchParams();
  params.set('granularity', opts.granularity);
  for (const id of opts.applicationIds ?? []) {
    params.append('application_ids', String(id));
  }
  return request<DashboardTrend>(`/dashboard/trend?${params.toString()}`, { signal });
}

/** "Vulnerability by Age" pie — CVE-age buckets, observation window on scan date. */
export function getVulnerabilityAge(
  opts: { period?: AgePeriod; from?: string; to?: string } = {},
  signal?: AbortSignal,
) {
  const params = new URLSearchParams();
  if (opts.period) params.set('period', opts.period);
  if (opts.from) params.set('date_from', opts.from);
  if (opts.to) params.set('date_to', opts.to);
  const qs = params.toString();
  return request<VulnerabilityAgeResponse>(
    `/dashboard/vulnerability-age${qs ? `?${qs}` : ''}`,
    { signal },
  );
}

// ─── Dashboard lifetime ──────────────────────────────────────────────────────
/**
 * Cumulative ("Your Analyzer, So Far") metrics. New in v2 — answers the
 * implicit "has the tool been working for me?" question. See
 * `docs/dashboard-redesign.md` §6.
 */
export function getDashboardLifetime(signal?: AbortSignal) {
  return request<LifetimeMetrics>('/dashboard/lifetime', { signal });
}

// ─── Dashboard v4 — advanced analytics ───────────────────────────────────────
import type {
  FindingsForecast,
  ExploitationOutlook,
  RemediationSummary,
  RiskMapResponse,
  RiskMatrixResponse,
  CopilotBriefing,
  CopilotAnswer,
} from '@/types';

/** Projected findings trajectory + velocity anomaly (metrics findings.forecast). */
export function getDashboardForecast(signal?: AbortSignal) {
  return request<FindingsForecast>('/dashboard/forecast', { signal });
}

/** Portfolio P(≥1 CVE exploited in 30d) composed from EPSS (+ coverage caveat). */
export function getDashboardExploitation(signal?: AbortSignal) {
  return request<ExploitationOutlook>('/dashboard/exploitation', { signal });
}

/** MTTR by severity, SLA countdowns/breaches, 30-day fix velocity. */
export function getDashboardRemediation(signal?: AbortSignal) {
  return request<RemediationSummary>('/dashboard/remediation', { signal });
}

export function getDashboardLifecycle(signal?: AbortSignal) {
  return request<DashboardLifecycle>('/dashboard/lifecycle', { signal });
}

export function getDashboardVex(signal?: AbortSignal) {
  return request<DashboardVex>('/dashboard/vex', { signal });
}

export function getDashboardHealth(signal?: AbortSignal) {
  return request<{
    completeness_score: number;
    missing_metadata: number;
    outdated_components: number;
  }>('/dashboard/health', { signal });
}

export function getDashboardRemediationStats(signal?: AbortSignal) {
  return request<{
    status_counts: Record<string, number>;
    aging_count: number;
    sla: {
      overdue: number;
      due_soon: number;
      ok: number;
    };
  }>('/dashboard/remediation-stats', { signal });
}

export function getSbomVexStatements(sbomId: number, signal?: AbortSignal) {
  return request<VexListResponse>(`/api/sboms/${sbomId}/vex`, { signal });
}

export function discoverSbomVexDocuments(sbomId: number, force = false, signal?: AbortSignal) {
  return request<VexDiscoveryResponse>(
    `/api/sboms/${sbomId}/vex/discover?force=${force ? 'true' : 'false'}`,
    {
      method: 'POST',
      signal,
    },
    120_000,
  );
}

export function uploadSbomVexDocument(
  sbomId: number,
  payload: {
    document: Record<string, unknown>;
    source_type?: string;
    source_name?: string;
    source_url?: string;
    author?: string;
    uploaded_by?: string;
  },
) {
  return request<VexImportResponse>(`/api/sboms/${sbomId}/vex`, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export function overrideVexStatement(
  componentId: number,
  vulnerabilityId: string,
  payload: VexOverridePayload,
  signal?: AbortSignal,
) {
  return request<VexListResponse['statements'][number]>(
    `/api/components/${componentId}/vulnerabilities/${encodeURIComponent(vulnerabilityId)}/vex-override`,
    {
      method: 'PATCH',
      body: JSON.stringify(payload),
      signal,
    },
  );
}

export function getVexOverrideHistory(componentId: number, vulnerabilityId: string, signal?: AbortSignal) {
  return request<VexOverrideHistoryResponse>(
    `/api/components/${componentId}/vulnerabilities/${encodeURIComponent(vulnerabilityId)}/vex-override/history`,
    { signal },
  );
}

export function exportSbomVexReportJson(sbomId: number, reportType = 'all', signal?: AbortSignal) {
  const params = new URLSearchParams({ format: 'json' });
  if (reportType && reportType !== 'all') params.set('report_type', reportType);
  return downloadBinary(`/api/sboms/${sbomId}/vex/report?${params.toString()}`, `sbom_${sbomId}_vex.json`, signal);
}

export function exportSbomVexReportCsv(sbomId: number, reportType = 'all', signal?: AbortSignal) {
  const params = new URLSearchParams({ format: 'csv' });
  if (reportType && reportType !== 'all') params.set('report_type', reportType);
  return downloadBinary(
    `/api/sboms/${sbomId}/vex/report?${params.toString()}`,
    `sbom_${sbomId}_vex${reportType && reportType !== 'all' ? `_${reportType}` : ''}.csv`,
    signal,
  );
}

export function exportSbomVexReportPack(sbomId: number, signal?: AbortSignal) {
  return downloadBinary(`/api/sboms/${sbomId}/reports/vex-pack`, `sbom_${sbomId}_vex_reports.zip`, signal);
}

/** Treemap cells — one per analysed SBOM, latest successful run. */
export function getDashboardRiskMap(signal?: AbortSignal) {
  return request<RiskMapResponse>('/dashboard/risk-map', { signal });
}

/** Impact × exploitability scatter points (CVSS vs EPSS, KEV-flagged). */
export function getDashboardRiskMatrix(limit = 300, signal?: AbortSignal) {
  return request<RiskMatrixResponse>(`/dashboard/risk-matrix?limit=${limit}`, {
    signal,
  });
}

// ─── AI Security Copilot ─────────────────────────────────────────────────────
/**
 * Executive briefing over the portfolio snapshot. Server-cached per data
 * state (≤6h); `force` regenerates. 403/404 → AI surface disabled (the
 * panel hides itself); 429 → budget cap; 502 → provider failure.
 * LLM latency can exceed the default 30s timeout — allow 90s.
 */
export function getCopilotBriefing(force = false, signal?: AbortSignal) {
  return request<CopilotBriefing>(
    `/api/ai/copilot/briefing${force ? '?force=true' : ''}`,
    { signal },
    90_000,
  );
}

/** One-shot grounded Q&A over the portfolio snapshot. */
export function askCopilot(question: string, signal?: AbortSignal) {
  return request<CopilotAnswer>(
    '/api/ai/copilot/ask',
    { method: 'POST', body: JSON.stringify({ question }), signal },
    90_000,
  );
}

// ─── Analysis-runs export & compare ──────────────────────────────────────────
export function compareRuns(runA: number, runB: number, signal?: AbortSignal) {
  return request<CompareRunsResult>(
    `/api/analysis-runs/compare?run_a=${runA}&run_b=${runB}`,
    { signal },
  );
}

// ─── Compare v2 (ADR-0008) ───────────────────────────────────────────────────
// `compareRunsV2` is the canonical method going forward. The v1 export
// `compareRuns` remains until the deprecated endpoint is removed (see
// ADR-0008 §1.2).
import type {
  CompareExportFormat,
  CompareRequest,
  CompareResult,
  RunSummary,
} from '@/types/compare';

export function compareRunsV2(body: CompareRequest, signal?: AbortSignal) {
  return request<CompareResult>('/api/v1/compare', {
    method: 'POST',
    body: JSON.stringify(body),
    signal,
  });
}

export function recentRuns(limit = 20, signal?: AbortSignal) {
  return request<RunSummary[]>(`/api/runs/recent?limit=${limit}`, { signal });
}

export function searchRuns(q: string, limit = 20, signal?: AbortSignal) {
  const params = new URLSearchParams({ q, limit: String(limit) });
  return request<RunSummary[]>(`/api/runs/search?${params.toString()}`, { signal });
}

/** Server-side compare export. Returns a typed Blob + filename pair. */
export async function exportCompare(
  cacheKey: string,
  format: CompareExportFormat,
  signal?: AbortSignal,
): Promise<{ blob: Blob; filename: string }> {
  const res = await performRequest(
    `/api/v1/compare/${cacheKey}/export`,
    {
      method: 'POST',
      body: JSON.stringify({ format }),
      signal,
    },
    60_000,
  );
  const cd = res.headers.get('Content-Disposition') || '';
  const match = /filename="?([^"]+)"?/.exec(cd);
  return {
    blob: await res.blob(),
    filename: match?.[1] || `compare.${format === 'markdown' ? 'md' : format}`,
  };
}

// CSV / SARIF export endpoints stream every finding for a run; for large runs
// this loops over thousands of rows server-side, so we use the long-running
// timeout (180s) consistent with PDF generation and analysis endpoints.
async function downloadBinary(
  path: string,
  fallbackName: string,
  signal?: AbortSignal,
  options: RequestInit = {},
): Promise<{ blob: Blob; filename: string }> {
  const { signal: optionSignal, ...rest } = options;
  const res = await performRequest(
    path,
    { method: 'GET', ...rest, signal: signal ?? optionSignal ?? undefined },
    180_000,
  );
  const cd = res.headers.get('Content-Disposition') || '';
  const match = /filename="?([^"]+)"?/.exec(cd);
  return { blob: await res.blob(), filename: match?.[1] || fallbackName };
}

export function exportRunCsv(runId: number) {
  return downloadBinary(`/api/analysis-runs/${runId}/export/csv`, `sbom_findings_${runId}.csv`);
}

export function exportRunSarif(runId: number) {
  return downloadBinary(`/api/analysis-runs/${runId}/export/sarif`, `sbom_findings_${runId}.sarif`);
}

// ─── Single-source analysis (power-user) ─────────────────────────────────────
export function analyzeSbomNvd(payload: AnalyzeSBOMPayload, signal?: AbortSignal) {
  return request<ConsolidatedAnalysisResult>('/analyze-sbom-nvd', {
    method: 'POST',
    body: JSON.stringify(payload),
    signal,
  }, 180_000);
}

export function analyzeSbomGithub(payload: AnalyzeSBOMPayload, signal?: AbortSignal) {
  return request<ConsolidatedAnalysisResult>('/analyze-sbom-github', {
    method: 'POST',
    body: JSON.stringify(payload),
    signal,
  }, 180_000);
}

export function analyzeSbomOsv(payload: AnalyzeSBOMPayload, signal?: AbortSignal) {
  return request<ConsolidatedAnalysisResult>('/analyze-sbom-osv', {
    method: 'POST',
    body: JSON.stringify(payload),
    signal,
  }, 180_000);
}

export function analyzeSbomVulnDb(payload: AnalyzeSBOMPayload, signal?: AbortSignal) {
  return request<ConsolidatedAnalysisResult>('/analyze-sbom-vulndb', {
    method: 'POST',
    body: JSON.stringify(payload),
    signal,
  }, 180_000);
}

// ─── Periodic analysis schedules ─────────────────────────────────────────────
// See app/routers/schedules.py for the server contract.

export function getProjectSchedule(projectId: number, signal?: AbortSignal) {
  return request<AnalysisSchedule>(`/api/projects/${projectId}/schedule`, { signal });
}

export function upsertProjectSchedule(
  projectId: number,
  payload: ScheduleUpsertPayload,
  signal?: AbortSignal,
) {
  return request<AnalysisSchedule>(`/api/projects/${projectId}/schedule`, {
    method: 'POST',
    body: JSON.stringify(payload),
    signal,
  });
}

export function patchProjectSchedule(
  projectId: number,
  payload: Partial<ScheduleUpsertPayload>,
  signal?: AbortSignal,
) {
  return request<AnalysisSchedule>(`/api/projects/${projectId}/schedule`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
    signal,
  });
}

export function deleteProjectSchedule(
  projectId: number,
  options: { permanent?: boolean } = {},
  signal?: AbortSignal,
) {
  const qs = options.permanent ? '?permanent=true' : '';
  return requestVoid(`/api/projects/${projectId}/schedule${qs}`, {
    method: 'DELETE',
    signal,
  });
}

export function getSbomSchedule(sbomId: number, signal?: AbortSignal) {
  return request<SbomScheduleResolved>(`/api/sboms/${sbomId}/schedule`, { signal });
}

export function upsertSbomSchedule(
  sbomId: number,
  payload: ScheduleUpsertPayload,
  signal?: AbortSignal,
) {
  return request<AnalysisSchedule>(`/api/sboms/${sbomId}/schedule`, {
    method: 'POST',
    body: JSON.stringify(payload),
    signal,
  });
}

export function patchSbomSchedule(
  sbomId: number,
  payload: Partial<ScheduleUpsertPayload>,
  signal?: AbortSignal,
) {
  return request<AnalysisSchedule>(`/api/sboms/${sbomId}/schedule`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
    signal,
  });
}

export function deleteSbomSchedule(
  sbomId: number,
  options: { permanent?: boolean } = {},
  signal?: AbortSignal,
) {
  const qs = options.permanent ? '?permanent=true' : '';
  return requestVoid(`/api/sboms/${sbomId}/schedule${qs}`, {
    method: 'DELETE',
    signal,
  });
}

export interface ListSchedulesFilter {
  scope?: 'PROJECT' | 'SBOM';
  enabled?: boolean;
  project_id?: number;
}

export function listSchedules(filter: ListSchedulesFilter = {}, signal?: AbortSignal) {
  const qs = new URLSearchParams();
  if (filter.scope) qs.set('scope', filter.scope);
  if (filter.enabled !== undefined) qs.set('enabled', String(filter.enabled));
  if (filter.project_id) qs.set('project_id', String(filter.project_id));
  const tail = qs.toString() ? `?${qs.toString()}` : '';
  return request<AnalysisSchedule[]>(`/api/schedules${tail}`, { signal });
}

export function pauseSchedule(scheduleId: number, signal?: AbortSignal) {
  return request<AnalysisSchedule>(`/api/schedules/${scheduleId}/pause`, {
    method: 'POST',
    signal,
  });
}

export function resumeSchedule(scheduleId: number, signal?: AbortSignal) {
  return request<AnalysisSchedule>(`/api/schedules/${scheduleId}/resume`, {
    method: 'POST',
    signal,
  });
}

export interface RunNowResult {
  status: string;
  schedule_id: number;
  sbom_ids: number[];
}

export function runScheduleNow(scheduleId: number, signal?: AbortSignal) {
  return request<RunNowResult>(`/api/schedules/${scheduleId}/run-now`, {
    method: 'POST',
    signal,
  });
}

// ─── AI fix generator ────────────────────────────────────────────────────────
import type {
  AiBatchDurationEstimate,
  AiBatchProgress,
  AiConnectionTestResult,
  AiCredential,
  AiCredentialCreateRequest,
  AiCredentialSettings,
  AiCredentialSettingsUpdateRequest,
  AiCredentialUpdateRequest,
  AiFindingFixEnvelope,
  AiFindingFixListResponse,
  AiPricingEntry,
  AiProviderCatalogEntry,
  AiProviderInfo,
  AiTestConnectionRequest,
  AiTopCachedItem,
  AiTriggerBatchRequest,
  AiTriggerBatchResponse,
  AiUsageSummary,
  AiUsageTrendResponse,
} from '@/types/ai';

/**
 * Read-only cache lookup for one finding. Returns ``null`` on 404
 * (no cached bundle) so callers can render an idle Generate state
 * without throwing. Never spends LLM budget — generation happens via
 * ``generateFindingAiFix`` (POST), which is only invoked on user click.
 */
export async function getFindingAiFix(
  findingId: number,
  args: { providerName?: string | null } = {},
  signal?: AbortSignal,
): Promise<AiFindingFixEnvelope | null> {
  const qs = args.providerName
    ? `?provider_name=${encodeURIComponent(args.providerName)}`
    : '';
  try {
    return await request<AiFindingFixEnvelope>(
      `/api/v1/findings/${findingId}/ai-fix${qs}`,
      { signal },
    );
  } catch (err) {
    if (err instanceof HttpError && err.status === 404) {
      return null;
    }
    throw err;
  }
}

/** Generate the AI fix for one finding (idempotent — returns cached if present). */
export function generateFindingAiFix(
  findingId: number,
  args: { providerName?: string | null } = {},
  signal?: AbortSignal,
): Promise<AiFindingFixEnvelope> {
  const qs = args.providerName
    ? `?provider_name=${encodeURIComponent(args.providerName)}`
    : '';
  return request<AiFindingFixEnvelope>(
    `/api/v1/findings/${findingId}/ai-fix${qs}`,
    { signal, method: 'POST' },
  );
}

/** Force a regenerate (bypass cache) for one finding. */
export function regenerateFindingAiFix(
  findingId: number,
  args: { providerName?: string | null } = {},
  signal?: AbortSignal,
): Promise<AiFindingFixEnvelope> {
  const qs = args.providerName
    ? `?provider_name=${encodeURIComponent(args.providerName)}`
    : '';
  return request<AiFindingFixEnvelope>(
    `/api/v1/findings/${findingId}/ai-fix:regenerate${qs}`,
    { signal, method: 'POST' },
  );
}

/** Trigger batch AI fix generation for an entire run. */
export function triggerRunAiFixes(
  runId: number,
  payload: AiTriggerBatchRequest = {},
  signal?: AbortSignal,
): Promise<AiTriggerBatchResponse> {
  return request<AiTriggerBatchResponse>(`/api/v1/runs/${runId}/ai-fixes`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
    signal,
  });
}

/** Cooperative cancel — sets a flag the worker checks before each LLM call. */
export function cancelRunAiFixes(
  runId: number,
  signal?: AbortSignal,
): Promise<{ run_id: number; cancel_requested: boolean }> {
  return request(`/api/v1/runs/${runId}/ai-fixes/cancel`, {
    method: 'POST',
    signal,
  });
}

/** Snapshot for clients that prefer polling over SSE. */
/**
 * Most-recent batch progress for a run. Resolves to ``null`` when the run
 * exists but has no AI fix batch (backend 204) — an idle run, not an error.
 * Callers must treat ``null`` as "nothing to track" (don't subscribe/poll).
 */
export function getRunAiFixProgress(
  runId: number,
  signal?: AbortSignal,
): Promise<AiBatchProgress | null> {
  return requestOrNull<AiBatchProgress>(`/api/v1/runs/${runId}/ai-fixes/progress`, {
    signal,
  });
}

/** List cached fix bundles for a run (table view). */
export function listRunAiFixes(
  runId: number,
  signal?: AbortSignal,
): Promise<AiFindingFixListResponse> {
  return request<AiFindingFixListResponse>(`/api/v1/runs/${runId}/ai-fixes`, { signal });
}

/** SSE URL — passed to ``EventSource``; full URL so the worker process and
 *  the browser don't have to share an origin in dev.
 *
 *  Legacy run-scoped stream — yields the most-recent batch's progress.
 *  Use ``aiFixBatchStreamUrl`` for per-batch SSE in the multi-batch flow. */
export function aiFixStreamUrl(runId: number): string {
  return `${BASE_URL}/api/v1/runs/${runId}/ai-fixes/stream`;
}

/** Per-batch SSE URL. Pin a stream to one batch_id so concurrent batches
 *  on the same run don't share an event source. */
export function aiFixBatchStreamUrl(runId: number, batchId: string): string {
  return `${BASE_URL}/api/v1/runs/${runId}/ai-fixes/batches/${batchId}/stream`;
}

/** List every batch (active + historical) for a run, newest-first. */
export function listRunAiBatches(
  runId: number,
  signal?: AbortSignal,
): Promise<import('@/types/ai').AiBatchListResponse> {
  return request(`/api/v1/runs/${runId}/ai-fixes/batches`, { signal });
}

/** One batch's durable record + live progress envelope. */
export function getRunAiBatch(
  runId: number,
  batchId: string,
  signal?: AbortSignal,
): Promise<import('@/types/ai').AiBatchDetailResponse> {
  return request(`/api/v1/runs/${runId}/ai-fixes/batches/${batchId}`, { signal });
}

/** Cooperative per-batch cancel. */
export function cancelRunAiBatch(
  runId: number,
  batchId: string,
  signal?: AbortSignal,
): Promise<{ run_id: number; batch_id: string; cancel_requested: boolean }> {
  return request(`/api/v1/runs/${runId}/ai-fixes/batches/${batchId}/cancel`, {
    method: 'POST',
    signal,
  });
}

/** Scope-aware pre-flight estimate. Replaces the legacy GET variant.
 *
 *  Backend resolves the scope to a finding-id list, counts cache hits
 *  via a single SQL join, and returns the duration / cost projection
 *  along with the multi-batch contention signal. */
export function estimateRunAiFixesScoped(
  runId: number,
  scope: import('@/types/ai').AiFixGenerationScope | null = null,
  signal?: AbortSignal,
): Promise<import('@/types/ai').AiScopedEstimateResponse> {
  return request(`/api/v1/runs/${runId}/ai-fixes/estimate`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ scope }),
    signal,
  });
}

/** Provider list for the Settings page (cached / displayed verbatim). */
export function listAiProviders(signal?: AbortSignal): Promise<AiProviderInfo[]> {
  return request<AiProviderInfo[]>(`/api/v1/ai/providers`, { signal });
}

export function listAiPricing(signal?: AbortSignal): Promise<AiPricingEntry[]> {
  return request<AiPricingEntry[]>(`/api/v1/ai/pricing`, { signal });
}

export function getAiUsageSummary(signal?: AbortSignal): Promise<AiUsageSummary> {
  return request<AiUsageSummary>(`/api/v1/ai/usage`, { signal });
}

/** Per-day cost / call / cache-hit series for the dashboard sparkline. */
export function getAiUsageTrend(
  args: { days?: number } = {},
  signal?: AbortSignal,
): Promise<AiUsageTrendResponse> {
  const days = args.days ?? 30;
  return request<AiUsageTrendResponse>(`/api/v1/ai/usage/trend?days=${days}`, { signal });
}

/** Top N most expensive cache entries — leaderboard tile. */
export function getAiTopCachedFixes(
  args: { limit?: number } = {},
  signal?: AbortSignal,
): Promise<AiTopCachedItem[]> {
  const limit = args.limit ?? 20;
  return request<AiTopCachedItem[]>(`/api/v1/ai/usage/top-cached?limit=${limit}`, { signal });
}

// ─── Phase 3 — credential CRUD + settings ────────────────────────────────

/** List every saved AI provider credential. */
export function listAiCredentials(signal?: AbortSignal): Promise<AiCredential[]> {
  return request<AiCredential[]>(`/api/v1/ai/credentials`, { signal });
}

export function getAiCredential(id: number, signal?: AbortSignal): Promise<AiCredential> {
  return request<AiCredential>(`/api/v1/ai/credentials/${id}`, { signal });
}

export function createAiCredential(
  body: AiCredentialCreateRequest,
  signal?: AbortSignal,
): Promise<AiCredential> {
  return request<AiCredential>(`/api/v1/ai/credentials`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal,
  });
}

export function updateAiCredential(
  id: number,
  body: AiCredentialUpdateRequest,
  signal?: AbortSignal,
): Promise<AiCredential> {
  return request<AiCredential>(`/api/v1/ai/credentials/${id}`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal,
  });
}

export function deleteAiCredential(id: number, signal?: AbortSignal): Promise<void> {
  return requestVoid(`/api/v1/ai/credentials/${id}`, { method: 'DELETE', signal });
}

export function setAiCredentialDefault(
  id: number,
  signal?: AbortSignal,
): Promise<AiCredential> {
  return request<AiCredential>(`/api/v1/ai/credentials/${id}/set-default`, {
    method: 'PUT',
    signal,
  });
}

export function setAiCredentialFallback(
  id: number,
  signal?: AbortSignal,
): Promise<AiCredential> {
  return request<AiCredential>(`/api/v1/ai/credentials/${id}/set-fallback`, {
    method: 'PUT',
    signal,
  });
}

/** Test an unsaved credential — used by the AddProviderDialog before Save. */
export function testAiCredentialUnsaved(
  body: AiTestConnectionRequest,
  signal?: AbortSignal,
): Promise<AiConnectionTestResult> {
  return request<AiConnectionTestResult>(`/api/v1/ai/credentials/test`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal,
  });
}

/** Re-test a saved credential — used by the ProviderCard "Test" button. */
export function testAiCredentialSaved(
  id: number,
  signal?: AbortSignal,
): Promise<AiConnectionTestResult> {
  return request<AiConnectionTestResult>(`/api/v1/ai/credentials/${id}/test`, {
    method: 'POST',
    signal,
  });
}

export function getAiCredentialSettings(signal?: AbortSignal): Promise<AiCredentialSettings> {
  return request<AiCredentialSettings>(`/api/v1/ai/settings`, { signal });
}

export function updateAiCredentialSettings(
  body: AiCredentialSettingsUpdateRequest,
  signal?: AbortSignal,
): Promise<AiCredentialSettings> {
  return request<AiCredentialSettings>(`/api/v1/ai/settings`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal,
  });
}

/** Static catalog driving the AddProviderDialog dropdown + form. */
export function listAiProviderCatalog(signal?: AbortSignal): Promise<AiProviderCatalogEntry[]> {
  return request<AiProviderCatalogEntry[]>(`/api/v1/ai/providers/available`, { signal });
}

export function getAiProviderCatalogEntry(
  name: string,
  signal?: AbortSignal,
): Promise<AiProviderCatalogEntry> {
  return request<AiProviderCatalogEntry>(
    `/api/v1/ai/providers/available/${encodeURIComponent(name)}`,
    { signal },
  );
}

/** Free-tier batch duration estimate (Phase 1 endpoint, used by FreeTierWarningDialog). */
export function getRunBatchEstimate(
  runId: number,
  signal?: AbortSignal,
): Promise<AiBatchDurationEstimate> {
  return request<AiBatchDurationEstimate>(
    `/api/v1/runs/${runId}/ai-fixes/estimate`,
    { signal },
  );
}

// ─── CVE detail modal ────────────────────────────────────────────────────────
import type { CveDetail, CveDetailWithContext } from '@/types';

/**
 * Fetch a single CVE's enriched detail payload.
 *
 * When ``scanId`` is supplied the scan-aware variant is used, which adds
 * component context + the recommended-upgrade callout. Without it, we
 * call the global endpoint.
 */
export function getCveDetail(
  args: { cveId: string; scanId?: number | null },
  signal?: AbortSignal,
): Promise<CveDetail | CveDetailWithContext> {
  const id = encodeURIComponent(args.cveId.trim().toUpperCase());
  if (args.scanId != null) {
    return request<CveDetailWithContext>(`/api/v1/scans/${args.scanId}/cves/${id}`, { signal });
  }
  return request<CveDetail>(`/api/v1/cves/${id}`, { signal });
}

// ─── CISA KEV catalog ───────────────────────────────────────────────────────

export function listKevVulnerabilities(
  args: KevListParams = {},
  signal?: AbortSignal,
): Promise<KevListResponse> {
  const params = new URLSearchParams();
  const textParams: Array<[keyof KevListParams, string]> = [
    ['q', 'q'],
    ['vendor', 'vendor'],
    ['product', 'product'],
    ['ransomware', 'ransomware'],
    ['date_added_from', 'date_added_from'],
    ['date_added_to', 'date_added_to'],
    ['due_date_from', 'due_date_from'],
    ['due_date_to', 'due_date_to'],
    ['catalog_version', 'catalog_version'],
    ['cwe', 'cwe'],
    ['sort_by', 'sort_by'],
    ['sort_order', 'sort_order'],
  ];
  textParams.forEach(([key, queryKey]) => {
    const value = args[key];
    if (typeof value === 'string' && value.trim()) params.set(queryKey, value.trim());
  });
  params.set('limit', String(args.limit ?? 50));
  params.set('offset', String(args.offset ?? 0));
  return request<KevListResponse>(`/api/v1/kev?${params.toString()}`, { signal });
}

export function getKevFilterOptions(
  args: { vendor?: string } = {},
  signal?: AbortSignal,
): Promise<KevFilterOptions> {
  const params = new URLSearchParams();
  if (args.vendor?.trim()) params.set('vendor', args.vendor.trim());
  const query = params.toString();
  return request<KevFilterOptions>(
    `/api/v1/kev/filter-options${query ? `?${query}` : ''}`,
    { signal },
  );
}

export function getKevVulnerability(
  cveId: string,
  signal?: AbortSignal,
): Promise<KevVulnerability> {
  return request<KevVulnerability>(
    `/api/v1/kev/${encodeURIComponent(cveId.trim().toUpperCase())}`,
    { signal },
  );
}

export function syncKevCatalog(signal?: AbortSignal): Promise<KevSyncResult> {
  return request<KevSyncResult>(
    '/api/v1/kev/sync',
    { method: 'POST', body: JSON.stringify({}), signal },
    120_000,
  );
}

export function upsertRemediation(projectId: number, payload: any, signal?: AbortSignal) {
  return request<any>(`/api/remediation?project_id=${projectId}`, {
    method: 'POST',
    body: JSON.stringify(payload),
    signal,
  });
}

// ─── Lifecycle provider admin ────────────────────────────────────────────────

export function listLifecycleProviders(signal?: AbortSignal): Promise<LifecycleProviderConfig[]> {
  return request<LifecycleProviderConfig[]>('/api/admin/lifecycle-providers', { signal });
}

export function updateLifecycleProvider(
  providerKey: string,
  body: LifecycleProviderUpdatePayload,
  signal?: AbortSignal,
): Promise<LifecycleProviderConfig> {
  return request<LifecycleProviderConfig>(`/api/admin/lifecycle-providers/${encodeURIComponent(providerKey)}`, {
    method: 'PUT',
    body: JSON.stringify(body),
    signal,
  });
}

export function setLifecycleProviderSecret(
  providerKey: string,
  body: { secret_name: string; secret_value: string },
  signal?: AbortSignal,
): Promise<LifecycleProviderSecretResult> {
  return request<LifecycleProviderSecretResult>(
    `/api/admin/lifecycle-providers/${encodeURIComponent(providerKey)}/secret`,
    {
      method: 'PUT',
      body: JSON.stringify(body),
      signal,
    },
  );
}

export function deleteLifecycleProviderSecret(
  providerKey: string,
  secretName: string,
  signal?: AbortSignal,
): Promise<void> {
  return requestVoid(
    `/api/admin/lifecycle-providers/${encodeURIComponent(providerKey)}/secret/${encodeURIComponent(secretName)}`,
    { method: 'DELETE', signal },
  );
}

export function testLifecycleProvider(
  providerKey: string,
  signal?: AbortSignal,
): Promise<LifecycleProviderTestResult> {
  return request<LifecycleProviderTestResult>(
    `/api/admin/lifecycle-providers/${encodeURIComponent(providerKey)}/test`,
    { method: 'POST', signal },
    65_000,
  );
}

export function syncLifecycleProvider(
  providerKey: string,
  signal?: AbortSignal,
): Promise<LifecycleProviderSyncResult> {
  return request<LifecycleProviderSyncResult>(
    `/api/admin/lifecycle-providers/${encodeURIComponent(providerKey)}/sync`,
    { method: 'POST', signal },
    65_000,
  );
}

export function listLifecycleVendorRecords(
  args: { search?: string; status?: string; ecosystem?: string; limit?: number; offset?: number } = {},
  signal?: AbortSignal,
): Promise<LifecycleVendorRecordListResponse> {
  const params = new URLSearchParams();
  if (args.search) params.set('search', args.search);
  if (args.status) params.set('status', args.status);
  if (args.ecosystem) params.set('ecosystem', args.ecosystem);
  if (args.limit) params.set('limit', String(args.limit));
  if (args.offset) params.set('offset', String(args.offset));
  const query = params.toString();
  return request<LifecycleVendorRecordListResponse>(
    `/api/admin/lifecycle-vendor-records${query ? `?${query}` : ''}`,
    { signal },
  );
}

export function createLifecycleVendorRecord(
  body: LifecycleVendorRecordPayload,
  signal?: AbortSignal,
): Promise<LifecycleVendorRecord> {
  return request<LifecycleVendorRecord>('/api/admin/lifecycle-vendor-records', {
    method: 'POST',
    body: JSON.stringify(body),
    signal,
  });
}

export function updateLifecycleVendorRecord(
  id: number,
  body: LifecycleVendorRecordPayload,
  signal?: AbortSignal,
): Promise<LifecycleVendorRecord> {
  return request<LifecycleVendorRecord>(`/api/admin/lifecycle-vendor-records/${id}`, {
    method: 'PUT',
    body: JSON.stringify(body),
    signal,
  });
}

export function deleteLifecycleVendorRecord(id: number, signal?: AbortSignal): Promise<void> {
  return requestVoid(`/api/admin/lifecycle-vendor-records/${id}`, { method: 'DELETE', signal });
}

export function importLifecycleVendorRecords(
  records: LifecycleVendorRecordPayload[],
  signal?: AbortSignal,
): Promise<{ created: number; errors: string[] }> {
  return request<{ created: number; errors: string[] }>('/api/admin/lifecycle-vendor-records/import', {
    method: 'POST',
    body: JSON.stringify({ records }),
    signal,
  });
}

export function exportLifecycleVendorRecords(signal?: AbortSignal): Promise<{ records: LifecycleVendorRecordPayload[] }> {
  return request<{ records: LifecycleVendorRecordPayload[] }>('/api/admin/lifecycle-vendor-records/export', { signal });
}
