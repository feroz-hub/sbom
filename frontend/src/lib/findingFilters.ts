import type { EnrichedFinding } from '@/types';

export interface FindingsFilterState {
  /** Free-text search across vuln_id, CVE aliases, title, description, component, CPE. */
  search: string;
  /** Server-side severity filter — passed to the API. */
  severityFilter: string;
  /** Multi-select source filter (NVD, OSV, GITHUB, VULNDB). Empty = all. */
  sources: string[];
  /** Inclusive CVSS range. */
  cvssMin: number;
  cvssMax: number;
  /** Minimum EPSS percentile (0..100). */
  epssMinPct: number;
  /** Show only findings on the CISA KEV catalog. */
  kevOnly: boolean;
  /** Show only findings with at least one fixed version. */
  hasFixOnly: boolean;
}

export const DEFAULT_FILTERS: FindingsFilterState = {
  search: '',
  severityFilter: '',
  sources: [],
  cvssMin: 0,
  cvssMax: 10,
  epssMinPct: 0,
  kevOnly: false,
  hasFixOnly: false,
};

const SEARCH_FIELDS: Array<keyof EnrichedFinding> = [
  'vuln_id',
  'severity',
  'component_name',
  'component_version',
  'cpe',
  'source',
  'title',
  'description',
  'cwe',
];

function searchableHay(f: EnrichedFinding): string {
  const parts: string[] = [];
  for (const k of SEARCH_FIELDS) {
    const v = f[k];
    if (typeof v === 'string') parts.push(v);
  }
  parts.push(...f.cve_aliases);
  return parts.join('  ').toLowerCase();
}

function fixedVersionsList(raw: string | null | undefined): string[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((v): v is string => typeof v === 'string') : [];
  } catch {
    return [];
  }
}

/**
 * Predicate that decides whether a finding satisfies the current filters.
 * Server-side severity is NOT applied here — that's pushed to the API.
 */
export function matchesFindingFilter(
  f: EnrichedFinding,
  filter: FindingsFilterState,
): boolean {
  if (filter.kevOnly && !f.in_kev) return false;
  if (filter.hasFixOnly && fixedVersionsList(f.fixed_versions).length === 0) return false;
  if (filter.cvssMin > 0 && (f.score ?? 0) < filter.cvssMin) return false;
  if (filter.cvssMax < 10 && (f.score ?? 0) > filter.cvssMax) return false;
  if (filter.epssMinPct > 0) {
    const pct = f.epss_percentile != null ? f.epss_percentile * 100 : 0;
    if (pct < filter.epssMinPct) return false;
  }
  if (filter.sources.length > 0) {
    const sources = (f.source ?? '').toUpperCase().split(',').map((s) => s.trim()).filter(Boolean);
    if (!filter.sources.some((s) => sources.includes(s.toUpperCase()))) return false;
  }
  if (filter.search.trim()) {
    const term = filter.search.trim().toLowerCase();
    if (!searchableHay(f).includes(term)) return false;
  }
  return true;
}

/** True when the filter state contains any active narrowing (excluding server severity). */
export function hasActiveFilters(filter: FindingsFilterState): boolean {
  return (
    filter.search.trim().length > 0 ||
    filter.sources.length > 0 ||
    filter.cvssMin > 0 ||
    filter.cvssMax < 10 ||
    filter.epssMinPct > 0 ||
    filter.kevOnly ||
    filter.hasFixOnly
  );
}

/** Count distinct active dimensions — used for the badge on the filter button. */
export function countActiveFilters(filter: FindingsFilterState): number {
  let n = 0;
  if (filter.search.trim()) n++;
  if (filter.sources.length > 0) n++;
  if (filter.cvssMin > 0 || filter.cvssMax < 10) n++;
  if (filter.epssMinPct > 0) n++;
  if (filter.kevOnly) n++;
  if (filter.hasFixOnly) n++;
  return n;
}

// ── Filter presets (localStorage) ────────────────────────────────────────────

const PRESET_STORAGE_KEY = 'findings-filter-presets';
const PRESET_VERSION = 1;
const MAX_PRESETS = 10;

export interface FindingsFilterPreset {
  id: string;
  name: string;
  filter: FindingsFilterState;
  createdAt: number;
}

interface PresetStorage {
  version: number;
  presets: FindingsFilterPreset[];
}

function readStorage(): FindingsFilterPreset[] {
  if (typeof window === 'undefined') return [];
  try {
    const raw = window.localStorage.getItem(PRESET_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as PresetStorage;
    if (!parsed || parsed.version !== PRESET_VERSION) return [];
    if (!Array.isArray(parsed.presets)) return [];
    return parsed.presets.filter(
      (p): p is FindingsFilterPreset =>
        p != null &&
        typeof p.id === 'string' &&
        typeof p.name === 'string' &&
        typeof p.filter === 'object' &&
        typeof p.createdAt === 'number',
    );
  } catch {
    return [];
  }
}

function writeStorage(presets: FindingsFilterPreset[]) {
  if (typeof window === 'undefined') return;
  try {
    const payload: PresetStorage = { version: PRESET_VERSION, presets };
    window.localStorage.setItem(PRESET_STORAGE_KEY, JSON.stringify(payload));
  } catch {
    // Quota / Safari private mode — silently drop; presets are optional UX.
  }
}

export function loadPresets(): FindingsFilterPreset[] {
  return readStorage().sort((a, b) => b.createdAt - a.createdAt);
}

export function savePreset(name: string, filter: FindingsFilterState): FindingsFilterPreset {
  const existing = readStorage();
  const trimmed = name.trim() || 'Untitled preset';
  const preset: FindingsFilterPreset = {
    id: `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`,
    name: trimmed.slice(0, 80),
    filter: { ...filter },
    createdAt: Date.now(),
  };
  // Replace by name if one already exists.
  const filtered = existing.filter((p) => p.name.toLowerCase() !== trimmed.toLowerCase());
  filtered.unshift(preset);
  writeStorage(filtered.slice(0, MAX_PRESETS));
  return preset;
}

export function deletePreset(id: string): void {
  const existing = readStorage();
  writeStorage(existing.filter((p) => p.id !== id));
}
