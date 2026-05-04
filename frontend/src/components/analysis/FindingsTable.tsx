'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Layers,
  Rows3,
  Rows4,
  Wrench,
} from 'lucide-react';
import { Alert } from '@/components/ui/Alert';
import {
  CveDetailDialog,
  useCveHoverPrefetch,
  type CveRowSeed,
} from '@/components/vulnerabilities/CveDetailDialog';
import {
  EmptyRow,
  SortableTh,
  Table,
  TableBody,
  TableHead,
  Td,
  Th,
} from '@/components/ui/Table';
import { SeverityBadge } from '@/components/ui/Badge';
import { CvssMeter } from '@/components/ui/CvssMeter';
import { KevBadge } from '@/components/ui/KevBadge';
import { EpssChip } from '@/components/ui/EpssChip';
import { SkeletonRow } from '@/components/ui/Spinner';
import { Pagination } from '@/components/ui/Pagination';
import { FindingFilterPanel } from '@/components/analysis/FindingFilterPanel';
import {
  DEFAULT_FILTERS,
  matchesFindingFilter,
  type FindingsFilterState,
} from '@/lib/findingFilters';
import { formatDateShort, truncate, cn } from '@/lib/utils';
import { useTableSort } from '@/hooks/useTableSort';
import { usePagination } from '@/hooks/usePagination';
import type { EnrichedFinding } from '@/types';

const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  UNKNOWN: 1,
};

type FindingSortKey =
  | 'vuln_id'
  | 'severity'
  | 'score'
  | 'risk_score'
  | 'epss'
  | 'component_name'
  | 'component_version'
  | 'published_on';

type Density = 'compact' | 'comfortable' | 'spacious';

const DENSITY_CLASS: Record<Density, string> = {
  compact: 'py-1.5 text-xs',
  comfortable: 'py-3 text-sm',
  spacious: 'py-4 text-sm',
};

const DENSITY_OPTIONS: Array<{ key: Density; label: string; Icon: typeof Rows3 }> = [
  { key: 'compact', label: 'Compact', Icon: Rows4 },
  { key: 'comfortable', label: 'Comfortable', Icon: Rows3 },
  { key: 'spacious', label: 'Spacious', Icon: Layers },
];

const DENSITY_STORAGE_KEY = 'findings-density';

interface FindingsTableProps {
  findings: EnrichedFinding[] | undefined;
  isLoading: boolean;
  error: Error | null;
  onSeverityChange?: (severity: string) => void;
  severityFilter?: string;
  /** Analysis run id — when present, the modal uses the scan-aware variant (component context + recommended upgrade). */
  runId?: number;
  /** Human-friendly scan label (typically the SBOM name) shown in the modal's component-context line. */
  scanName?: string | null;
  /**
   * Feature flag — when false, the findings table reverts to the legacy
   * ``<a target="_blank">`` outbound link to GHSA / NVD. Drives the
   * Phase-5 rollback path. Default: ``true``.
   */
  cveModalEnabled?: boolean;
  /**
   * Master flag for the AI remediation section inside the CVE modal.
   * When true the section renders alongside the deterministic CVE data.
   */
  aiFixesEnabled?: boolean;
  /** Provider name shown in the empty-state CTA copy. */
  aiProviderLabel?: string;
}

/**
 * Outbound link for the legacy "open in GHSA / NVD" path used when the
 * in-app modal is disabled by feature flag (rollback). GHSA IDs go to
 * github.com; CVE IDs go to nvd.nist.gov. Returns ``null`` when neither
 * pattern matches, so the call site can render plain text.
 */
function legacyVulnUrl(vulnId: string | null, referenceUrl: string | null): string | null {
  if (referenceUrl) return referenceUrl;
  if (!vulnId) return null;
  if (vulnId.startsWith('GHSA-')) return `https://github.com/advisories/${vulnId}`;
  if (vulnId.startsWith('CVE-')) return `https://nvd.nist.gov/vuln/detail/${vulnId}`;
  return null;
}

function findingToSeed(f: EnrichedFinding): CveRowSeed {
  return {
    vuln_id: f.vuln_id,
    severity: f.severity,
    score: f.score,
    cvss_version: f.cvss_version,
    in_kev: f.in_kev,
    epss: f.epss,
    epss_percentile: f.epss_percentile,
    component_name: f.component_name,
    component_version: f.component_version,
    source: f.source,
  };
}

function parseJsonStringList(raw: string | null | undefined): string[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((v): v is string => typeof v === 'string') : [];
  } catch {
    return [];
  }
}

function loadDensity(): Density {
  if (typeof window === 'undefined') return 'comfortable';
  const stored = window.localStorage.getItem(DENSITY_STORAGE_KEY);
  if (stored === 'compact' || stored === 'comfortable' || stored === 'spacious') {
    return stored;
  }
  return 'comfortable';
}

function SourceChips({ source }: { source: string | null }) {
  if (!source) return <span className="text-xs text-hcl-muted">—</span>;
  const parts = source.split(',').map((s) => s.trim()).filter(Boolean);
  const colorMap: Record<string, string> = {
    NVD: 'border-indigo-200 bg-indigo-50 text-indigo-700 dark:border-indigo-800 dark:bg-indigo-950/50 dark:text-indigo-200',
    OSV: 'border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-200',
    GITHUB: 'border-purple-200 bg-purple-50 text-purple-700 dark:border-purple-800 dark:bg-purple-950/50 dark:text-purple-200',
    GHSA: 'border-purple-200 bg-purple-50 text-purple-700 dark:border-purple-800 dark:bg-purple-950/50 dark:text-purple-200',
    VULNDB: 'border-cyan-200 bg-cyan-50 text-cyan-800 dark:border-cyan-800 dark:bg-cyan-950/50 dark:text-cyan-200',
  };
  return (
    <div className="flex flex-wrap gap-1">
      {parts.map((s) => (
        <span
          key={s}
          className={cn(
            'inline-block rounded border px-1.5 py-0.5 text-[10px] font-semibold',
            colorMap[s.toUpperCase()] ??
              'border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-300',
          )}
        >
          {s}
        </span>
      ))}
    </div>
  );
}

function FixedVersionPills({ raw }: { raw: string | null | undefined }) {
  const versions = parseJsonStringList(raw);
  if (versions.length === 0) {
    return <span className="text-xs text-hcl-muted">—</span>;
  }
  const visible = versions.slice(0, 2);
  const overflow = versions.length - visible.length;
  return (
    <div className="flex flex-wrap gap-1">
      {visible.map((v) => (
        <span
          key={v}
          title={`Upgrade to ${v}`}
          className="inline-flex items-center gap-1 rounded-full border border-emerald-200 bg-emerald-50 px-1.5 py-0.5 font-metric text-[10px] font-semibold text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-300"
        >
          <Wrench className="h-2.5 w-2.5" aria-hidden />
          {v}
        </span>
      ))}
      {overflow > 0 && (
        <span
          title={versions.slice(2).join(', ')}
          className="inline-flex items-center rounded-full border border-emerald-200 bg-emerald-50/40 px-1.5 py-0.5 font-metric text-[10px] font-semibold text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950/30 dark:text-emerald-300"
        >
          +{overflow}
        </span>
      )}
    </div>
  );
}

function AliasChips({ aliases }: { aliases: string[] }) {
  if (aliases.length === 0) return null;
  const visible = aliases.slice(0, 1);
  const overflow = aliases.length - visible.length;
  return (
    <div className="flex flex-wrap items-center gap-1">
      {visible.map((a) => (
        <span
          key={a}
          className="rounded border border-border-subtle bg-surface-muted px-1 py-px font-mono text-[10px] text-hcl-muted"
        >
          {a}
        </span>
      ))}
      {overflow > 0 && (
        <span
          title={aliases.slice(1).join(', ')}
          className="rounded border border-border-subtle bg-surface-muted px-1 py-px font-mono text-[10px] text-hcl-muted"
        >
          +{overflow}
        </span>
      )}
    </div>
  );
}

export function FindingsTable({
  findings,
  isLoading,
  error,
  onSeverityChange,
  severityFilter = '',
  runId,
  scanName,
  cveModalEnabled = true,
  aiFixesEnabled = false,
  aiProviderLabel,
}: FindingsTableProps) {
  const [filter, setFilter] = useState<FindingsFilterState>(() => ({
    ...DEFAULT_FILTERS,
    severityFilter,
  }));
  const [density, setDensity] = useState<Density>('comfortable');
  const [expandedRows, setExpandedRows] = useState<Record<number, boolean>>({});

  // Active CVE for the in-app detail modal. We keep a single page-level
  // dialog instance and swap the active CVE — one query at a time, no
  // per-row dialog mount.
  const [activeCve, setActiveCve] = useState<
    { id: string; seed: CveRowSeed; findingId: number | null } | null
  >(null);
  const { onHoverStart, onHoverEnd } = useCveHoverPrefetch();
  const openCve = useCallback(
    (f: EnrichedFinding) => {
      if (!f.vuln_id) return;
      setActiveCve({
        id: f.vuln_id,
        seed: findingToSeed(f),
        findingId: typeof f.id === 'number' ? f.id : null,
      });
    },
    [],
  );

  // Hydrate density from localStorage after mount.
  useEffect(() => {
    setDensity(loadDensity());
  }, []);

  // Persist density.
  useEffect(() => {
    if (typeof window === 'undefined') return;
    window.localStorage.setItem(DENSITY_STORAGE_KEY, density);
  }, [density]);

  // Keep server severity in sync if the controller resets it externally.
  useEffect(() => {
    setFilter((prev) =>
      prev.severityFilter === severityFilter ? prev : { ...prev, severityFilter },
    );
  }, [severityFilter]);

  const sourceOptions = useMemo(() => {
    const set = new Set<string>();
    findings?.forEach((f) => {
      if (f.source?.trim()) {
        f.source.split(',').forEach((s) => {
          const trimmed = s.trim().toUpperCase();
          if (trimmed) set.add(trimmed);
        });
      }
    });
    return Array.from(set).sort((a, b) => a.localeCompare(b));
  }, [findings]);

  const filteredFindings = useMemo(() => {
    if (!findings?.length) return [];
    return findings.filter((f) => matchesFindingFilter(f, filter));
  }, [findings, filter]);

  const sortAccessors = useMemo(
    () => ({
      vuln_id: (f: EnrichedFinding) => f.vuln_id ?? '',
      severity: (f: EnrichedFinding) =>
        SEVERITY_RANK[(f.severity ?? 'UNKNOWN').toUpperCase()] ?? 0,
      score: (f: EnrichedFinding) => f.score ?? -1,
      risk_score: (f: EnrichedFinding) => f.risk_score,
      epss: (f: EnrichedFinding) => f.epss,
      component_name: (f: EnrichedFinding) => (f.component_name ?? '').toLowerCase(),
      component_version: (f: EnrichedFinding) => f.component_version ?? '',
      published_on: (f: EnrichedFinding) => f.published_on ?? '',
    }),
    [],
  );

  const { sort, sortedRows, toggle: toggleSort } = useTableSort<EnrichedFinding, FindingSortKey>(
    filteredFindings,
    sortAccessors,
    { initialKey: 'risk_score', initialDirection: 'desc' },
  );

  const pagination = usePagination<EnrichedFinding>(sortedRows, {
    defaultPageSize: 25,
    storageKey: 'findings',
  });

  // Reset to first page when filters narrow.
  useEffect(() => {
    pagination.resetPage();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter.search, filter.kevOnly, filter.hasFixOnly, filter.cvssMin, filter.cvssMax, filter.epssMinPct, filter.sources, filter.severityFilter]);

  if (error) {
    return (
      <Alert variant="error" title="Could not load findings">
        {error.message}
      </Alert>
    );
  }

  const total = findings?.length ?? 0;
  const shown = filteredFindings.length;
  const cellPadding = DENSITY_CLASS[density];
  const COL_COUNT = 9; // chevron + vuln + severity + cvss + epss + risk + component + sources + fix

  const toggleExpand = (id: number) => {
    setExpandedRows((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  return (
    <div className="space-y-3">
      <FindingFilterPanel
        filter={filter}
        onChange={setFilter}
        sourceOptions={sourceOptions}
        onSeverityServerChange={
          onSeverityChange
            ? (sev) => {
                setFilter((prev) => ({ ...prev, severityFilter: sev }));
                onSeverityChange(sev);
              }
            : undefined
        }
        totalCount={total}
        filteredCount={shown}
      />

      {/* Density toggle */}
      <div className="flex items-center justify-end gap-1.5 px-1">
        <span className="text-[11px] font-medium uppercase tracking-wider text-hcl-muted">
          Density
        </span>
        <div className="inline-flex overflow-hidden rounded-lg border border-border bg-surface">
          {DENSITY_OPTIONS.map(({ key, label, Icon }) => (
            <button
              key={key}
              type="button"
              onClick={() => setDensity(key)}
              aria-pressed={density === key}
              title={label}
              className={cn(
                'inline-flex h-7 items-center gap-1 px-2 text-[11px] font-medium transition-colors duration-base',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/30',
                density === key
                  ? 'bg-primary text-white'
                  : 'text-hcl-muted hover:bg-surface-muted hover:text-hcl-navy',
              )}
            >
              <Icon className="h-3 w-3" aria-hidden />
              <span className="hidden sm:inline">{label}</span>
            </button>
          ))}
        </div>
      </div>

      <div className="overflow-hidden rounded-xl border border-border bg-surface shadow-card">
        <Table striped ariaLabel="Vulnerability findings">
          <TableHead>
            <tr>
              <Th className="w-8 px-2"><span className="sr-only">Expand</span></Th>
              <SortableTh
                sortKey="vuln_id"
                activeKey={sort.key}
                direction={sort.direction}
                onToggle={(k) => toggleSort(k as FindingSortKey)}
              >
                Vulnerability
              </SortableTh>
              <SortableTh
                sortKey="severity"
                activeKey={sort.key}
                direction={sort.direction}
                onToggle={(k) => toggleSort(k as FindingSortKey)}
              >
                Severity
              </SortableTh>
              <SortableTh
                sortKey="score"
                activeKey={sort.key}
                direction={sort.direction}
                onToggle={(k) => toggleSort(k as FindingSortKey)}
              >
                CVSS
              </SortableTh>
              <SortableTh
                sortKey="epss"
                activeKey={sort.key}
                direction={sort.direction}
                onToggle={(k) => toggleSort(k as FindingSortKey)}
              >
                EPSS
              </SortableTh>
              <SortableTh
                sortKey="risk_score"
                activeKey={sort.key}
                direction={sort.direction}
                onToggle={(k) => toggleSort(k as FindingSortKey)}
              >
                Risk
              </SortableTh>
              <SortableTh
                sortKey="component_name"
                activeKey={sort.key}
                direction={sort.direction}
                onToggle={(k) => toggleSort(k as FindingSortKey)}
              >
                Component
              </SortableTh>
              <Th>Sources</Th>
              <Th>Fix</Th>
            </tr>
          </TableHead>
          <TableBody>
            {isLoading ? (
              Array.from({ length: 6 }).map((_, i) => <SkeletonRow key={i} cols={COL_COUNT} />)
            ) : !findings?.length ? (
              <EmptyRow cols={COL_COUNT} message="No findings found for this run." />
            ) : !filteredFindings.length ? (
              <EmptyRow
                cols={COL_COUNT}
                message="No findings match the active filters. Clear them to see all rows."
              />
            ) : (
              pagination.pageItems.flatMap((f) => {
                const isExpanded = !!expandedRows[f.id];
                const aliases = f.cve_aliases.filter((a) => a !== f.vuln_id);
                const cwes = (f.cwe ?? '').split(',').map((s) => s.trim()).filter(Boolean);
                const fixedVersions = parseJsonStringList(f.fixed_versions);

                return [
                  <tr
                    key={f.id}
                    className={cn(
                      'group transition-colors hover:bg-hcl-light/40',
                      f.in_kev && 'bg-red-50/30 dark:bg-red-950/10',
                      isExpanded && 'bg-surface-muted/50',
                    )}
                  >
                    <td className={cn('px-2 align-top', cellPadding)}>
                      <button
                        type="button"
                        onClick={() => toggleExpand(f.id)}
                        aria-label={isExpanded ? 'Collapse details' : 'Expand details'}
                        aria-expanded={isExpanded}
                        className="inline-flex h-6 w-6 items-center justify-center rounded-md text-hcl-muted transition-colors hover:bg-surface-muted hover:text-hcl-navy focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/30"
                      >
                        {isExpanded ? (
                          <ChevronDown className="h-3.5 w-3.5" aria-hidden />
                        ) : (
                          <ChevronRight className="h-3.5 w-3.5" aria-hidden />
                        )}
                      </button>
                    </td>
                    <td className={cn('px-4 align-top', cellPadding)}>
                      <div className="flex flex-col gap-1">
                        <div className="flex items-center gap-1.5">
                          {f.vuln_id ? (
                            cveModalEnabled ? (
                              <button
                                type="button"
                                onClick={() => openCve(f)}
                                onMouseEnter={onHoverStart(f.vuln_id, runId ?? null)}
                                onMouseLeave={onHoverEnd}
                                onFocus={onHoverStart(f.vuln_id, runId ?? null)}
                                onBlur={onHoverEnd}
                                className="inline-flex items-center gap-1 rounded font-mono text-xs font-semibold text-hcl-blue hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40"
                                aria-label={`Open CVE detail for ${f.vuln_id}`}
                              >
                                {f.vuln_id}
                              </button>
                            ) : (() => {
                              const legacyUrl = legacyVulnUrl(f.vuln_id, f.reference_url);
                              return legacyUrl ? (
                                <a
                                  href={legacyUrl}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="inline-flex items-center gap-1 font-mono text-xs font-semibold text-hcl-blue hover:underline"
                                >
                                  {f.vuln_id}
                                  <ExternalLink className="h-3 w-3" aria-hidden />
                                </a>
                              ) : (
                                <span className="font-mono text-xs font-semibold text-foreground/90">
                                  {f.vuln_id}
                                </span>
                              );
                            })()
                          ) : (
                            <span className="font-mono text-xs font-semibold text-foreground/90">
                              —
                            </span>
                          )}
                          {f.in_kev && <KevBadge compact={density === 'compact'} />}
                        </div>
                        <AliasChips aliases={aliases} />
                      </div>
                    </td>
                    <td className={cn('px-4 align-top', cellPadding)}>
                      <SeverityBadge severity={f.severity ?? 'UNKNOWN'} />
                    </td>
                    <td className={cn('px-4 align-top', cellPadding)}>
                      <CvssMeter
                        score={f.score}
                        version={f.cvss_version}
                        compact={density === 'compact'}
                      />
                    </td>
                    <td className={cn('px-4 align-top', cellPadding)}>
                      <EpssChip
                        epss={f.epss}
                        percentile={f.epss_percentile}
                        compact={density === 'compact'}
                      />
                    </td>
                    <td className={cn('px-4 align-top font-metric font-semibold tabular-nums text-hcl-navy', cellPadding)}>
                      <span
                        className={cn(
                          'inline-flex items-center gap-1',
                          f.risk_score >= 50 && 'text-red-700 dark:text-red-400',
                          f.risk_score >= 20 && f.risk_score < 50 && 'text-orange-700 dark:text-orange-400',
                        )}
                        title={`cvss ${(f.score ?? 0).toFixed(1)} × (1 + 5×${f.epss.toFixed(3)}) × (${f.in_kev ? '2 KEV' : '1'}) = ${f.risk_score.toFixed(2)}`}
                      >
                        {f.risk_score.toFixed(1)}
                      </span>
                    </td>
                    <td className={cn('px-4 align-top', cellPadding)}>
                      <div className="flex flex-col">
                        <span className="font-medium text-hcl-navy">{f.component_name || '—'}</span>
                        <span className="font-mono text-[11px] text-hcl-muted">
                          {f.component_version || '—'}
                        </span>
                      </div>
                    </td>
                    <td className={cn('px-4 align-top', cellPadding)}>
                      <SourceChips source={f.source} />
                    </td>
                    <td className={cn('px-4 align-top', cellPadding)}>
                      <FixedVersionPills raw={f.fixed_versions} />
                    </td>
                  </tr>,
                  isExpanded && (
                    <tr key={`${f.id}-detail`} className="bg-surface-muted/40 motion-fade-in">
                      <td colSpan={COL_COUNT} className="px-4 py-4">
                        <ExpandedDetail
                          finding={f}
                          aliases={aliases}
                          cwes={cwes}
                          fixedVersions={fixedVersions}
                          onAliasOpen={(alias) =>
                            setActiveCve({
                              id: alias,
                              seed: { ...findingToSeed(f), vuln_id: alias },
                              findingId: typeof f.id === 'number' ? f.id : null,
                            })
                          }
                        />
                      </td>
                    </tr>
                  ),
                ];
              })
            )}
          </TableBody>
        </Table>

        {!isLoading && filteredFindings.length > 0 ? (
          <Pagination
            page={pagination.page}
            pageSize={pagination.pageSize}
            total={pagination.total}
            totalPages={pagination.totalPages}
            rangeStart={pagination.rangeStart}
            rangeEnd={pagination.rangeEnd}
            hasPrev={pagination.hasPrev}
            hasNext={pagination.hasNext}
            onPageChange={pagination.setPage}
            onPageSizeChange={pagination.setPageSize}
            itemNoun="finding"
          />
        ) : null}
      </div>

      {cveModalEnabled ? (
        <CveDetailDialog
          cveId={activeCve?.id ?? null}
          seed={activeCve?.seed ?? null}
          scanId={runId ?? null}
          scanName={scanName ?? null}
          open={activeCve !== null}
          onOpenChange={(open) => {
            if (!open) setActiveCve(null);
          }}
          onSwitchCve={(newId) =>
            setActiveCve((prev) =>
              prev ? { id: newId, seed: prev.seed, findingId: prev.findingId } : prev,
            )
          }
          findingId={activeCve?.findingId ?? null}
          aiFixesEnabled={aiFixesEnabled}
          aiProviderLabel={aiProviderLabel}
        />
      ) : null}
    </div>
  );
}

interface ExpandedDetailProps {
  finding: EnrichedFinding;
  aliases: string[];
  cwes: string[];
  fixedVersions: string[];
  /** Open the CVE detail modal for an alternate ID. */
  onAliasOpen?: (alias: string) => void;
}

function ExpandedDetail({ finding: f, aliases, cwes, fixedVersions, onAliasOpen }: ExpandedDetailProps) {
  const description =
    f.description && f.description !== f.vuln_id
      ? f.description
      : f.title && f.title !== f.vuln_id
        ? f.title
        : null;

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
      <div className="lg:col-span-2 space-y-3">
        {description && (
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-wider text-hcl-muted">
              Description
            </p>
            <p className="mt-1 text-sm leading-relaxed text-foreground/90">
              {truncate(description, 600)}
            </p>
          </div>
        )}
        {f.title && f.title !== description && f.title !== f.vuln_id && (
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-wider text-hcl-muted">
              Title
            </p>
            <p className="mt-1 text-sm text-foreground/90">{f.title}</p>
          </div>
        )}
        <div className="flex flex-wrap items-start gap-x-6 gap-y-2 text-xs">
          {f.cpe && (
            <div className="min-w-0">
              <span className="block text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
                CPE
              </span>
              <span className="block max-w-md truncate font-mono text-[11px] text-foreground/80" title={f.cpe}>
                {f.cpe}
              </span>
            </div>
          )}
          {f.attack_vector && (
            <div>
              <span className="block text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
                Attack vector
              </span>
              <span className="block font-mono text-[11px] text-foreground/80">{f.attack_vector}</span>
            </div>
          )}
          {f.published_on && (
            <div>
              <span className="block text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
                Published
              </span>
              <span className="font-metric block text-[11px] tabular-nums text-foreground/80">
                {formatDateShort(f.published_on)}
              </span>
            </div>
          )}
          {f.vector && (
            <div className="min-w-0">
              <span className="block text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
                CVSS vector
              </span>
              <span className="block max-w-md truncate font-mono text-[11px] text-foreground/80" title={f.vector}>
                {f.vector}
              </span>
            </div>
          )}
        </div>
      </div>

      <div className="space-y-3">
        {/* Risk score breakdown */}
        <div className="rounded-lg border border-border-subtle bg-surface px-3 py-2">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
            Risk score
          </p>
          <p className="font-metric mt-0.5 text-2xl font-bold tabular-nums text-hcl-navy">
            {f.risk_score.toFixed(2)}
          </p>
          <p className="mt-1 font-mono text-[10px] leading-relaxed text-hcl-muted">
            {(f.score ?? 0).toFixed(1)} cvss × {(1 + 5 * f.epss).toFixed(2)} epss
            {f.in_kev && ' × 2.0 KEV'}
          </p>
        </div>

        {cwes.length > 0 && (
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
              CWE
            </p>
            <div className="mt-1 flex flex-wrap gap-1">
              {cwes.map((cwe) => (
                <a
                  key={cwe}
                  href={`https://cwe.mitre.org/data/definitions/${cwe.replace(/^CWE-/, '')}.html`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-mono inline-flex items-center gap-1 rounded border border-border-subtle bg-surface px-1.5 py-0.5 text-[11px] text-hcl-blue hover:underline"
                >
                  {cwe}
                  <ExternalLink className="h-2.5 w-2.5" aria-hidden />
                </a>
              ))}
            </div>
          </div>
        )}

        {fixedVersions.length > 0 && (
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
              Fixed versions
            </p>
            <div className="mt-1 flex flex-wrap gap-1">
              {fixedVersions.map((v) => (
                <span
                  key={v}
                  className="font-metric inline-flex items-center gap-1 rounded-full border border-emerald-200 bg-emerald-50 px-2 py-0.5 text-[11px] font-semibold text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-300"
                >
                  <Wrench className="h-3 w-3" aria-hidden />
                  {v}
                </span>
              ))}
            </div>
          </div>
        )}

        {aliases.length > 0 && (
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-hcl-muted">
              All aliases
            </p>
            <div className="mt-1 flex flex-wrap gap-1">
              {aliases.map((a) =>
                onAliasOpen ? (
                  <button
                    key={a}
                    type="button"
                    onClick={() => onAliasOpen(a)}
                    className="font-mono inline-flex items-center gap-1 rounded border border-border-subtle bg-surface px-1.5 py-0.5 text-[11px] text-hcl-blue hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40"
                    aria-label={`Open CVE detail for ${a}`}
                  >
                    {a}
                  </button>
                ) : (
                  <span
                    key={a}
                    className="font-mono inline-flex items-center gap-1 rounded border border-border-subtle bg-surface px-1.5 py-0.5 text-[11px] text-foreground/80"
                  >
                    {a}
                  </span>
                ),
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
