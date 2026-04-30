import type {
  Project,
  SBOMSource,
  SBOMComponent,
  AnalysisRun,
  AnalysisFinding,
  EnrichedFinding,
  DashboardStats,
  DashboardPosture,
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
  DashboardTrend,
  CompareRunsResult,
  AnalysisSchedule,
  SbomScheduleResolved,
  ScheduleUpsertPayload,
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

export const BASE_URL = resolveBaseUrl();

// ─── Typed HTTP error ─────────────────────────────────────────────────────────
export class HttpError extends Error {
  status: number;
  code?: string;
  constructor(message: string, status: number, code?: string) {
    super(message);
    this.name = 'HttpError';
    this.status = status;
    this.code = code;
  }
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
async function performRequest(
  path: string,
  options: RequestInit & { signal?: AbortSignal } = {},
  timeoutMs = 30_000,
): Promise<Response> {
  const url = `${BASE_URL}${path}`;
  const res = await fetchWithTimeout(
    url,
    {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
      ...options,
    },
    timeoutMs,
  );

  if (!res.ok) {
    let message = `HTTP ${res.status}: ${res.statusText}`;
    let code: string | undefined;
    try {
      const body = await res.json();
      if (body?.detail) {
        if (typeof body.detail === 'string') {
          message = body.detail;
        } else if (typeof body.detail === 'object' && !Array.isArray(body.detail) && body.detail.message) {
          message = body.detail.message;
          code = body.detail.code;
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
    throw new HttpError(message, res.status, code);
  }

  return res;
}

// JSON-returning request — for endpoints that return a typed body.
async function request<T>(
  path: string,
  options: RequestInit & { signal?: AbortSignal } = {},
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

// Void request — for endpoints that return no body (DELETE, etc.). No casts.
async function requestVoid(
  path: string,
  options: RequestInit & { signal?: AbortSignal } = {},
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

export function deleteProject(id: number, signal?: AbortSignal) {
  return requestVoid(`/api/projects/${id}?confirm=yes`, {
    method: 'DELETE',
    signal,
  });
}

// ─── SBOMs ───────────────────────────────────────────────────────────────────
export function getSboms(page = 1, pageSize = 50, signal?: AbortSignal) {
  return request<SBOMSource[]>(`/api/sboms?page=${page}&page_size=${pageSize}`, { signal });
}

export function getSbom(id: number, signal?: AbortSignal) {
  return request<SBOMSource>(`/api/sboms/${id}`, { signal });
}

export function createSbom(payload: CreateSBOMPayload, signal?: AbortSignal) {
  return request<SBOMSource>('/api/sboms', {
    method: 'POST',
    body: JSON.stringify(payload),
    signal,
  });
}

export function updateSbom(
  id: number,
  userId: number | string,
  payload: UpdateSBOMPayload,
  signal?: AbortSignal
) {
  return request<SBOMSource>(`/api/sboms/${id}?user_id=${userId}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
    signal,
  });
}

export function deleteSbom(id: number, userId: number | string, signal?: AbortSignal) {
  return requestVoid(`/api/sboms/${id}?user_id=${userId}&confirm=yes`, {
    method: 'DELETE',
    signal,
  });
}

export function getSbomComponents(sbomId: number, signal?: AbortSignal) {
  return request<SBOMComponent[]>(`/api/sboms/${sbomId}/components`, { signal });
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

// ─── Dashboard trend ─────────────────────────────────────────────────────────
export function getDashboardTrend(days = 30, signal?: AbortSignal) {
  return request<DashboardTrend>(`/dashboard/trend?days=${days}`, { signal });
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
): Promise<{ blob: Blob; filename: string }> {
  const res = await performRequest(path, { method: 'GET', signal }, 180_000);
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

export function deleteProjectSchedule(projectId: number, signal?: AbortSignal) {
  return requestVoid(`/api/projects/${projectId}/schedule`, {
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

export function deleteSbomSchedule(sbomId: number, signal?: AbortSignal) {
  return requestVoid(`/api/sboms/${sbomId}/schedule`, {
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
