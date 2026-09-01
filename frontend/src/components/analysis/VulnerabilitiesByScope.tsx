'use client';

import { useMemo, useState } from 'react';
import Link from 'next/link';
import { useQuery } from '@tanstack/react-query';
import { ChevronDown, ChevronRight, ShieldAlert } from 'lucide-react';
import { Alert } from '@/components/ui/Alert';
import { Select } from '@/components/ui/Select';
import { Surface } from '@/components/ui/Surface';
import { PageSpinner } from '@/components/ui/Spinner';
import { Table, TableBody, TableHead, Td, Th } from '@/components/ui/Table';
import { getVulnerabilities, type VulnerabilityRow } from '@/lib/api';
import { severityBg } from '@/lib/utils';

const SEVERITY_OPTIONS = [
  { value: '', label: 'All severities' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'unknown', label: 'Unknown' },
];

interface ProductGroup {
  key: string;
  productName: string;
  productId: number | null;
  rows: VulnerabilityRow[];
}

interface ProjectGroup {
  key: string;
  projectName: string;
  count: number;
  products: ProductGroup[];
}

/**
 * Group the flat row list into Project → Product buckets.
 *
 * Grouping happens client-side on purpose: the endpoint returns one ordered
 * page sorted by descending score, and grouping here preserves that ordering
 * inside every bucket without the server having to materialise a nested shape.
 * Rows with no project or product still get a bucket — an unassigned SBOM's
 * vulnerabilities must not silently vanish from a security view.
 */
function groupRows(rows: VulnerabilityRow[]): ProjectGroup[] {
  const projects = new Map<string, ProjectGroup>();

  for (const row of rows) {
    const projectName = row.project_name?.trim() || (row.project_id != null ? `Project #${row.project_id}` : 'Unassigned project');
    const productName = row.product_name?.trim() || (row.product_id != null ? `Product #${row.product_id}` : 'Unassigned product');
    const projectKey = String(row.project_id ?? projectName);
    const productKey = `${projectKey}::${row.product_id ?? productName}`;

    let project = projects.get(projectKey);
    if (!project) {
      project = { key: projectKey, projectName, count: 0, products: [] };
      projects.set(projectKey, project);
    }
    project.count += 1;

    let product = project.products.find((p) => p.key === productKey);
    if (!product) {
      product = { key: productKey, productName, productId: row.product_id, rows: [] };
      project.products.push(product);
    }
    product.rows.push(row);
  }

  const ordered = Array.from(projects.values());
  ordered.sort((a, b) => b.count - a.count || a.projectName.localeCompare(b.projectName));
  for (const project of ordered) {
    project.products.sort((a, b) => b.rows.length - a.rows.length || a.productName.localeCompare(b.productName));
  }
  return ordered;
}

/** `fixed_versions` is a JSON array stored as text; render the first entry. */
function fixHint(raw: string | null): string {
  if (!raw) return '—';
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed) && parsed.length > 0) return String(parsed[0]);
  } catch {
    // Not JSON — some providers write a bare version string.
    const trimmed = raw.trim();
    if (trimmed && trimmed !== '[]') return trimmed;
  }
  return '—';
}

export interface VulnerabilitiesByScopeProps {
  severity: string;
  onSeverityChange: (value: string) => void;
}

/**
 * Portfolio-wide vulnerability list, grouped by project then product.
 *
 * Scoped to each SBOM's latest successful run — the same scope as the
 * dashboard severity pie, so clicking a slice lands here on the same number
 * it showed. Previously that click routed to a single analysis run and
 * displayed a fraction of the portfolio count.
 */
export function VulnerabilitiesByScope({ severity, onSeverityChange }: VulnerabilitiesByScopeProps) {
  const [collapsed, setCollapsed] = useState<Set<string>>(() => new Set());

  const { data, isLoading, error } = useQuery({
    queryKey: ['vulnerabilities', { severity }],
    queryFn: ({ signal }) => getVulnerabilities({ severity: severity || undefined, page_size: 2000 }, signal),
  });

  const groups = useMemo(() => groupRows(data?.findings ?? []), [data]);

  const toggle = (key: string) =>
    setCollapsed((current) => {
      const next = new Set(current);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const severityLabel = SEVERITY_OPTIONS.find((o) => o.value === severity)?.label ?? 'All severities';
  const total = data?.total ?? 0;
  const returned = data?.returned ?? 0;

  return (
    <div className="space-y-4">
      <Surface variant="elevated">
        <div className="flex flex-wrap items-end justify-between gap-4 p-4">
          <div className="w-full min-w-[12rem] sm:w-56">
            <Select label="Severity" value={severity} onChange={(e) => onSeverityChange(e.target.value)}>
              {SEVERITY_OPTIONS.map(({ value, label }) => (
                <option key={value || '__all__'} value={value}>
                  {label}
                </option>
              ))}
            </Select>
          </div>
          <p className="text-sm text-hcl-muted">
            {isLoading ? (
              'Loading vulnerabilities…'
            ) : (
              <>
                <span className="font-semibold text-hcl-navy">{total.toLocaleString()}</span>{' '}
                {severityLabel.toLowerCase() === 'all severities'
                  ? 'vulnerabilities'
                  : `${severityLabel.toLowerCase()} vulnerabilities`}{' '}
                across {groups.length.toLocaleString()}{' '}
                {groups.length === 1 ? 'project' : 'projects'}
                {returned < total ? ` · showing the top ${returned.toLocaleString()} by score` : ''}
              </>
            )}
          </p>
        </div>
      </Surface>

      {error ? (
        <Alert variant="error" title="Could not load vulnerabilities">
          {(error as Error).message}
        </Alert>
      ) : isLoading ? (
        <PageSpinner />
      ) : groups.length === 0 ? (
        <Surface variant="elevated">
          <div className="flex flex-col items-center gap-2 p-10 text-center">
            <ShieldAlert className="h-6 w-6 text-hcl-muted" aria-hidden />
            <p className="text-sm text-hcl-muted">
              No {severityLabel.toLowerCase() === 'all severities' ? '' : `${severityLabel.toLowerCase()} `}
              vulnerabilities in the latest scan of any SBOM.
            </p>
          </div>
        </Surface>
      ) : (
        groups.map((project) => {
          const projectCollapsed = collapsed.has(project.key);
          return (
            <Surface key={project.key} variant="elevated" className="overflow-hidden">
              <button
                type="button"
                onClick={() => toggle(project.key)}
                aria-expanded={!projectCollapsed}
                className="flex w-full items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40"
              >
                {projectCollapsed ? (
                  <ChevronRight className="h-4 w-4 shrink-0 text-hcl-muted" aria-hidden />
                ) : (
                  <ChevronDown className="h-4 w-4 shrink-0 text-hcl-muted" aria-hidden />
                )}
                <span className="min-w-0 flex-1 truncate font-semibold text-hcl-navy">
                  {project.projectName}
                </span>
                <span className="shrink-0 text-sm tabular-nums text-hcl-muted">
                  {project.count.toLocaleString()}
                </span>
              </button>

              {!projectCollapsed &&
                project.products.map((product) => {
                  const productKey = product.key;
                  const productCollapsed = collapsed.has(productKey);
                  return (
                    <div key={productKey} className="border-t border-border">
                      <button
                        type="button"
                        onClick={() => toggle(productKey)}
                        aria-expanded={!productCollapsed}
                        className="flex w-full items-center gap-3 bg-surface-muted/40 px-4 py-2 pl-10 text-left transition-colors hover:bg-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40"
                      >
                        {productCollapsed ? (
                          <ChevronRight className="h-3.5 w-3.5 shrink-0 text-hcl-muted" aria-hidden />
                        ) : (
                          <ChevronDown className="h-3.5 w-3.5 shrink-0 text-hcl-muted" aria-hidden />
                        )}
                        <span className="min-w-0 flex-1 truncate text-sm font-medium text-hcl-navy">
                          {product.productName}
                        </span>
                        <span className="shrink-0 text-xs tabular-nums text-hcl-muted">
                          {product.rows.length.toLocaleString()}
                        </span>
                      </button>

                      {!productCollapsed && (
                        <Table bordered ariaLabel={`${product.productName} vulnerabilities`}>
                          <TableHead>
                            <tr>
                              <Th>Vulnerability</Th>
                              <Th>Severity</Th>
                              <Th>Score</Th>
                              <Th>Component</Th>
                              <Th>Version</Th>
                              <Th>Fixed In</Th>
                              <Th>SBOM</Th>
                              <Th>Source</Th>
                            </tr>
                          </TableHead>
                          <TableBody>
                            {product.rows.map((row) => (
                              <tr key={row.finding_id}>
                                <Td className="whitespace-nowrap font-mono text-xs">
                                  <Link
                                    href={`/analysis/${row.run_id}`}
                                    className="font-medium text-hcl-navy hover:text-hcl-blue hover:underline"
                                  >
                                    {row.vuln_id}
                                  </Link>
                                </Td>
                                <Td>
                                  <span
                                    className={`inline-flex rounded-full border px-2 py-0.5 text-xs font-medium ${severityBg(row.severity)}`}
                                  >
                                    {row.severity}
                                  </span>
                                </Td>
                                <Td className="tabular-nums text-hcl-muted">
                                  {row.score != null ? row.score.toFixed(1) : '—'}
                                </Td>
                                <Td className="text-hcl-muted">{row.component_name || '—'}</Td>
                                <Td className="whitespace-nowrap text-hcl-muted">
                                  {row.component_version || '—'}
                                </Td>
                                <Td className="whitespace-nowrap text-hcl-muted">
                                  {fixHint(row.fixed_versions)}
                                </Td>
                                <Td className="text-hcl-muted">
                                  {row.sbom_id != null ? (
                                    <Link
                                      href={`/sboms/${row.sbom_id}`}
                                      className="hover:text-hcl-blue hover:underline"
                                    >
                                      {row.sbom_name || `SBOM #${row.sbom_id}`}
                                    </Link>
                                  ) : (
                                    row.sbom_name || '—'
                                  )}
                                </Td>
                                <Td className="whitespace-nowrap text-hcl-muted">{row.source || '—'}</Td>
                              </tr>
                            ))}
                          </TableBody>
                        </Table>
                      )}
                    </div>
                  );
                })}
            </Surface>
          );
        })
      )}
    </div>
  );
}
