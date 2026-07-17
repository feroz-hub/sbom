import type { EnrichedFinding, MatchStrategy } from '@/types';

/**
 * Two-state collapse of {@link MatchReason} mirroring PR4's
 * MatchReasonBadge. ``all`` disables the filter; ``verified`` selects
 * rows where ``match_reason === 'matched'``; ``not_verified`` selects
 * rows with any conservative-keep reason. Null reasons match neither
 * verified nor not_verified — pre-filter rows are filtered OUT when a
 * non-``all`` value is set.
 */
export type MatchReasonFilter = 'all' | 'verified' | 'not_verified';
export type KevStatusFilter = 'all' | 'kev' | 'non-kev';
export type RansomwareStatusFilter = 'all' | 'known' | 'not-known';

export interface FindingsFilterState {
  /** Free-text search across finding identity, component, and KEV context. */
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
  /** Show only KEV findings with known ransomware campaign use. */
  ransomwareOnly: boolean;
  /** Three-state KEV membership filter. */
  kevStatus: KevStatusFilter;
  /** Three-state known-ransomware filter. */
  ransomwareStatus: RansomwareStatusFilter;
  /** Exact, case-insensitive vendor selection. Empty = all. */
  vendor: string;
  /** Exact, case-insensitive product selection. Empty = all. */
  product: string;
  /** Show only findings with at least one fixed version. */
  hasFixOnly: boolean;
  /** Roadmap #1 — two-state trust filter mirroring MatchReasonBadge. */
  matchReasonFilter: MatchReasonFilter;
  /** Roadmap #3 — minimum confidence threshold in [0.0, 1.0]. 0 disables. */
  matchConfidenceMin: number;
  /** Roadmap #6 — multi-select strategy filter. Empty = all. */
  matchStrategies: MatchStrategy[];
}

/**
 * High-EPSS percentile threshold (0–100) — the boundary for "likely to be
 * exploited" used by the dashboard's exploitability signal and its drill-down.
 * Single source of truth so the dashboard tile, the `?epss=` deep-link, the
 * destination `epssMinPct` filter, and the (Phase 2) backend aggregate all
 * agree. 90 ≈ EpssChip's "High" band; tune here only.
 */
export const HIGH_EPSS_PERCENTILE = 90;

export const DEFAULT_FILTERS: FindingsFilterState = {
  search: '',
  severityFilter: '',
  sources: [],
  cvssMin: 0,
  cvssMax: 10,
  epssMinPct: 0,
  kevOnly: false,
  ransomwareOnly: false,
  kevStatus: 'all',
  ransomwareStatus: 'all',
  vendor: '',
  product: '',
  hasFixOnly: false,
  matchReasonFilter: 'all',
  matchConfidenceMin: 0,
  matchStrategies: [],
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
  'required_action',
  'vendor_project',
  'product',
  'ransomware_status',
  'notes',
];

function normalize(value: unknown): string {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

function searchableValues(f: EnrichedFinding): string[] {
  const parts: string[] = [];
  for (const k of SEARCH_FIELDS) {
    const v = f[k];
    if (typeof v === 'string') parts.push(normalize(v));
  }
  parts.push(...(f.cve_aliases ?? []).map(normalize));
  return parts;
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

export function isKnownRansomwareFinding(f: EnrichedFinding): boolean {
  return [f.ransomware_status, f.known_ransomware_campaign_use]
    .some((value) => normalize(value) === 'known');
}

export function isKevFinding(f: EnrichedFinding): boolean {
  return f.in_kev === true || f.is_kev === true;
}

export function effectiveKevStatus(filter: FindingsFilterState): KevStatusFilter {
  if (filter.kevStatus === 'kev' || filter.kevStatus === 'non-kev') {
    return filter.kevStatus;
  }
  return filter.kevOnly ? 'kev' : 'all';
}

export function effectiveRansomwareStatus(
  filter: FindingsFilterState,
): RansomwareStatusFilter {
  if (filter.ransomwareStatus === 'known' || filter.ransomwareStatus === 'not-known') {
    return filter.ransomwareStatus;
  }
  return filter.ransomwareOnly ? 'known' : 'all';
}

/**
 * Predicate that decides whether a finding satisfies the current filters.
 * Server-side severity is NOT applied here — that's pushed to the API.
 */
export function matchesFindingFilter(
  f: EnrichedFinding,
  filter: FindingsFilterState,
): boolean {
  const kevStatus = effectiveKevStatus(filter);
  const ransomwareStatus = effectiveRansomwareStatus(filter);
  const isKev = isKevFinding(f);
  const isKnownRansomware = isKnownRansomwareFinding(f);

  if (kevStatus === 'kev' && !isKev) return false;
  if (kevStatus === 'non-kev' && isKev) return false;
  if (ransomwareStatus === 'known' && !isKnownRansomware) return false;
  if (ransomwareStatus === 'not-known' && isKnownRansomware) return false;
  if (
    filter.severityFilter &&
    normalize(f.severity) !== normalize(filter.severityFilter)
  ) return false;
  if (filter.vendor && normalize(f.vendor_project) !== normalize(filter.vendor)) return false;
  if (filter.product && normalize(f.product) !== normalize(filter.product)) return false;
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
    const term = normalize(filter.search);
    if (!searchableValues(f).some((value) => value.includes(term))) return false;
  }
  // Roadmap #1 — two-state trust filter. ``all`` is the no-op default.
  // Null reasons (flag-off scans, non-NVD sources) match neither
  // ``verified`` nor ``not_verified`` and are filtered out when a
  // non-``all`` value is set. Matches the MatchReasonBadge collapse
  // exactly so the chip and the badge stay coherent.
  if (filter.matchReasonFilter === 'verified') {
    if (f.match_reason !== 'matched') return false;
  } else if (filter.matchReasonFilter === 'not_verified') {
    if (!f.match_reason || f.match_reason === 'matched') return false;
  }
  // Roadmap #3 — minimum confidence threshold. A null confidence is
  // filtered out when the threshold is set; the analyst chose to
  // narrow to scored findings only.
  if (filter.matchConfidenceMin > 0) {
    if (f.match_confidence == null || f.match_confidence < filter.matchConfidenceMin) {
      return false;
    }
  }
  // Roadmap #6 — strategy multi-select. Null strategy never matches a
  // chip (pre-tag rows are filtered out when any chip is active).
  if (filter.matchStrategies.length > 0) {
    if (!f.match_strategy || !filter.matchStrategies.includes(f.match_strategy)) {
      return false;
    }
  }
  return true;
}

/** True when the filter state contains any active narrowing. */
export function hasActiveFilters(filter: FindingsFilterState): boolean {
  return (
    filter.search.trim().length > 0 ||
    filter.severityFilter.length > 0 ||
    filter.sources.length > 0 ||
    filter.cvssMin > 0 ||
    filter.cvssMax < 10 ||
    filter.epssMinPct > 0 ||
    effectiveKevStatus(filter) !== 'all' ||
    effectiveRansomwareStatus(filter) !== 'all' ||
    filter.vendor.length > 0 ||
    filter.product.length > 0 ||
    filter.hasFixOnly ||
    filter.matchReasonFilter !== 'all' ||
    filter.matchConfidenceMin > 0 ||
    filter.matchStrategies.length > 0
  );
}

/** Count distinct active dimensions — used for the badge on the filter button. */
export function countActiveFilters(filter: FindingsFilterState): number {
  let n = 0;
  if (filter.search.trim()) n++;
  if (filter.severityFilter) n++;
  if (filter.sources.length > 0) n++;
  if (filter.cvssMin > 0 || filter.cvssMax < 10) n++;
  if (filter.epssMinPct > 0) n++;
  if (effectiveKevStatus(filter) !== 'all') n++;
  if (effectiveRansomwareStatus(filter) !== 'all') n++;
  if (filter.vendor) n++;
  if (filter.product) n++;
  if (filter.hasFixOnly) n++;
  if (filter.matchReasonFilter !== 'all') n++;
  if (filter.matchConfidenceMin > 0) n++;
  if (filter.matchStrategies.length > 0) n++;
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

function isKevStatus(value: unknown): value is KevStatusFilter {
  return value === 'all' || value === 'kev' || value === 'non-kev';
}

function isRansomwareStatus(value: unknown): value is RansomwareStatusFilter {
  return value === 'all' || value === 'known' || value === 'not-known';
}

/** Merge persisted/legacy partial state into today's complete filter contract. */
export function normalizeFindingsFilter(
  raw: Partial<FindingsFilterState> | null | undefined,
): FindingsFilterState {
  const input = raw ?? {};
  const kevStatus = isKevStatus(input.kevStatus)
    ? input.kevStatus
    : input.kevOnly
      ? 'kev'
      : 'all';
  const ransomwareStatus = isRansomwareStatus(input.ransomwareStatus)
    ? input.ransomwareStatus
    : input.ransomwareOnly
      ? 'known'
      : 'all';

  return {
    ...DEFAULT_FILTERS,
    ...input,
    sources: Array.isArray(input.sources) ? input.sources : [],
    matchStrategies: Array.isArray(input.matchStrategies) ? input.matchStrategies : [],
    kevStatus,
    ransomwareStatus,
    kevOnly: kevStatus === 'kev',
    ransomwareOnly: ransomwareStatus === 'known',
    vendor: typeof input.vendor === 'string' ? input.vendor : '',
    product: typeof input.product === 'string' ? input.product : '',
  };
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
    ).map((preset) => ({
      ...preset,
      filter: normalizeFindingsFilter(preset.filter),
    }));
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
    filter: normalizeFindingsFilter(filter),
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
