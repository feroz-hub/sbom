import type {
  Project,
  SBOMSource,
  SBOMComponent,
  AnalysisRun,
  AnalysisFinding,
  DashboardStats,
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
} from '@/types';

async function request<T>(
  path: string,
  options: RequestInit & { signal?: AbortSignal } = {}
): Promise<T> {
  // Use relative paths — Next.js rewrites proxy them to the backend (no CORS)
  const url = path;
  const res = await fetch(url, {
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
    ...options,
  });

  if (!res.ok) {
    let message = `HTTP ${res.status}: ${res.statusText}`;
    try {
      const body = await res.json();
      if (body?.detail) {
        message = typeof body.detail === 'string'
          ? body.detail
          : Array.isArray(body.detail)
            ? body.detail.map((e: { msg?: string; loc?: string[] }) =>
                `${e.loc?.slice(1).join('.')} — ${e.msg}`
              ).join('; ')
            : JSON.stringify(body.detail);
      }
    } catch {
      // ignore parse errors
    }
    throw new Error(message);
  }

  // 204 No Content
  if (res.status === 204) {
    return undefined as unknown as T;
  }

  return res.json() as Promise<T>;
}

// ─── Health ──────────────────────────────────────────────────────────────────
export function getHealth(signal?: AbortSignal) {
  return request<{ status: string }>('/health', { signal });
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
  // user_id is optional on the backend — omit it so any user can update
  return request<Project>(`/api/projects/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
    signal,
  });
}

export function deleteProject(id: number, signal?: AbortSignal) {
  return request<void>(`/api/projects/${id}?confirm=yes`, {
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
  return request<void>(`/api/sboms/${id}?user_id=${userId}&confirm=yes`, {
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
  });
}

// ─── Consolidated Analysis ───────────────────────────────────────────────────
export function analyzeConsolidated(payload: AnalyzeSBOMPayload, signal?: AbortSignal) {
  return request<ConsolidatedAnalysisResult>('/analyze-sbom-consolidated', {
    method: 'POST',
    body: JSON.stringify(payload),
    signal,
  });
}

// ─── Analysis Runs ────────────────────────────────────────────────────────────
export interface RunsFilter {
  sbom_id?: number;
  project_id?: number;
  run_status?: string;
  page?: number;
  page_size?: number;
}

export function getRuns(filter: RunsFilter = {}, signal?: AbortSignal) {
  const params = new URLSearchParams();
  if (filter.sbom_id !== undefined) params.set('sbom_id', String(filter.sbom_id));
  if (filter.project_id !== undefined) params.set('project_id', String(filter.project_id));
  if (filter.run_status) params.set('run_status', filter.run_status);
  params.set('page', String(filter.page ?? 1));
  params.set('page_size', String(filter.page_size ?? 50));
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

export async function exportRunsJson(filter: RunsFilter = {}): Promise<void> {
  const params = new URLSearchParams();
  if (filter.sbom_id !== undefined) params.set('sbom_id', String(filter.sbom_id));
  if (filter.project_id !== undefined) params.set('project_id', String(filter.project_id));
  if (filter.run_status) params.set('run_status', filter.run_status);
  params.set('page', '1');
  params.set('page_size', '1000');
  const data = await request<AnalysisRun[]>(`/api/runs?${params.toString()}`);
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'analysis_runs.json';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ─── PDF Report ───────────────────────────────────────────────────────────────
export async function downloadPdfReport(payload: PDFReportPayload): Promise<Blob> {
  const url = '/api/pdf-report';
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    let message = `HTTP ${res.status}: ${res.statusText}`;
    try {
      const body = await res.json();
      if (body?.detail) {
        message = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail);
      }
    } catch {
      // ignore
    }
    throw new Error(message);
  }
  return res.blob();
}

// ─── SBOM Types ───────────────────────────────────────────────────────────────
export function getSbomTypes(signal?: AbortSignal) {
  return request<SBOMType[]>('/api/types', { signal });
}
