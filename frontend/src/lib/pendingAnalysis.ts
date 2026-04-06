/**
 * sessionStorage utilities for tracking in-flight background analyses.
 * Entries survive page refresh but are cleared when the tab closes.
 */

interface PendingEntry {
  startedAt: number;  // Date.now()
  sbomName: string;
}

const KEY = 'pending_analyses';
const MAX_AGE_MS = 3 * 60 * 1000; // give up after 3 minutes

function read(): Record<string, PendingEntry> {
  try {
    return JSON.parse(sessionStorage.getItem(KEY) ?? '{}');
  } catch {
    return {};
  }
}

function write(data: Record<string, PendingEntry>) {
  try {
    sessionStorage.setItem(KEY, JSON.stringify(data));
  } catch {
    // sessionStorage may be unavailable (SSR, private mode quota)
  }
}

export function addPendingAnalysis(sbomId: number, sbomName: string) {
  const data = read();
  data[String(sbomId)] = { startedAt: Date.now(), sbomName };
  write(data);
}

export function removePendingAnalysis(sbomId: number) {
  const data = read();
  delete data[String(sbomId)];
  write(data);
}

export function getStillPendingAnalyses(): Array<{ sbomId: number; sbomName: string }> {
  const data = read();
  const now = Date.now();
  return Object.entries(data)
    .filter(([, entry]) => now - entry.startedAt < MAX_AGE_MS)
    .map(([id, entry]) => ({ sbomId: Number(id), sbomName: entry.sbomName }));
}

export function clearStalePendingAnalyses() {
  const data = read();
  const now = Date.now();
  const filtered: Record<string, PendingEntry> = {};
  for (const [id, entry] of Object.entries(data)) {
    if (now - entry.startedAt < MAX_AGE_MS) filtered[id] = entry;
  }
  write(filtered);
}
