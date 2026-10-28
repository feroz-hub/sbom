/** Principal-scoped browser recovery markers. Legacy/unscoped markers cannot authorize recovery. */
export interface PendingAnalysis { sbomId: (string | number); sbomName: string; scope: string; startedAt: number; checkedAt: number; runId?: number }
const KEY = 'pending_analyses', MAX_AGE_MS = 3 * 60 * 1000;
function read(): Record<string, PendingAnalysis> {
  try { const value = JSON.parse(sessionStorage.getItem(KEY) ?? '{}'); return value && typeof value === 'object' && !Array.isArray(value) ? value : {}; } catch { return {}; }
}
function write(value: Record<string, PendingAnalysis>) { try { sessionStorage.setItem(KEY, JSON.stringify(value)); } catch { /* unavailable storage */ } }
export function addPendingAnalysis(sbomId: (string | number), sbomName: string, scope = 'legacy', runId?: number) {
  const value = read(); const key = `${scope}:${sbomId}`, previous = value[key];
  value[key] = { sbomId, sbomName, scope, startedAt: previous?.startedAt ?? Date.now(), checkedAt: Date.now(), runId: runId ?? previous?.runId }; write(value);
}
export function removePendingAnalysis(sbomId: (string | number), scope = 'legacy') { const value = read(); delete value[`${scope}:${sbomId}`]; write(value); }
export function getStillPendingAnalyses(scope?: string): PendingAnalysis[] {
  return Object.values(read()).filter(entry => entry && Boolean(entry.sbomId) && Number.isFinite(entry.startedAt) && Number.isFinite(entry.checkedAt) && typeof entry.scope === 'string' && entry.scope !== 'legacy' && (!scope || entry.scope === scope));
}
export function pendingAnalysisExpired(entry: PendingAnalysis) { return Date.now() - entry.checkedAt > MAX_AGE_MS; }
export function clearStalePendingAnalyses() {
  const value = read(); for (const [key, entry] of Object.entries(value)) if (!entry?.scope || entry.scope === 'legacy' || !Number.isSafeInteger(entry.sbomId)) delete value[key]; write(value);
}
