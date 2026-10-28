'use client';

import Link from 'next/link';
import { useState } from 'react';
import { CveDetailDialog } from '@/components/vulnerabilities/CveDetailDialog';
import { useQuery } from '@tanstack/react-query';
import { BarChart, Bar, Cell, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie } from 'recharts';
import { Surface, SurfaceHeader, SurfaceContent } from '@/components/ui/Surface';
import { Skeleton } from '@/components/ui/Spinner';
import { useAuth } from '@/hooks/useAuth';
import { getDashboardPriorityFindings, getDashboardRuns, getAnalysisConfig, type DashboardFilterScope, type DashboardPriorityFinding } from '@/lib/api';
import { dashboardDrilldownUrl } from '@/lib/dashboardScopeUrl';
import { formatDate } from '@/lib/utils';
import type { SeverityData, AnalysisRun } from '@/types';

export const OVERVIEW_SEVERITIES = [
  { key: 'critical', name: 'Critical', color: '#C0392B' },
  { key: 'high', name: 'High', color: '#D4680A' },
  { key: 'medium', name: 'Medium', color: '#B8860B' },
  { key: 'low', name: 'Low', color: '#0067B1' },
  { key: 'unknown', name: 'Unknown', color: '#5B7083' },
] as const;

export function SeverityBars({ data, loading, onSelect }: {
  data?: SeverityData; loading: boolean; onSelect: (key: 'critical' | 'high' | 'medium' | 'low') => void;
}) {
  const rows = OVERVIEW_SEVERITIES.map(s => ({ ...s, count: data?.[s.key] ?? 0 }));
  return <Surface className="h-full min-w-0" elevation={1}>
    <SurfaceHeader><h2 className="text-sm font-semibold text-hcl-navy">Severity breakdown</h2></SurfaceHeader>
    <SurfaceContent>
      {loading ? <Skeleton className="h-48 w-full" /> : !data ? <p className="text-sm text-hcl-muted">Data unavailable</p> : <>
        <ResponsiveContainer width="100%" height={165}>
          <BarChart data={rows} margin={{ left: -25, right: 0, top: 12 }}>
            <XAxis dataKey="name" tick={{ fontSize: 9, fill: 'var(--color-hcl-muted)' }} axisLine={false} tickLine={false} />
            <YAxis allowDecimals={false} tick={{ fontSize: 10, fill: 'var(--color-hcl-muted)' }} axisLine={false} tickLine={false} />
            <Tooltip contentStyle={{ background: 'var(--color-surface)', borderColor: 'var(--color-border)', borderRadius: 10 }} />
            <Bar dataKey="count" name="Findings" radius={[5, 5, 0, 0]} isAnimationActive={false}>
              {rows.map(s => <Cell key={s.key} fill={s.color} />)}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
        <div className="mt-3 flex flex-wrap gap-2" aria-label="Severity counts">
          {rows.map(s => s.key === 'unknown' ? <span key={s.key} className="text-xs text-hcl-muted">Unknown: {s.count}</span> :
            <button key={s.key} disabled={!s.count} onClick={() => onSelect(s.key as 'critical' | 'high' | 'medium' | 'low')} className="rounded px-1 text-xs text-hcl-muted enabled:hover:text-hcl-blue focus-visible:ring-2 focus-visible:ring-hcl-blue">{s.name}: {s.count}</button>)}
        </div>
      </>}
    </SurfaceContent>
  </Surface>;
}

interface Health { completeness_score?: number; missing_metadata?: number; outdated_components?: number }
interface Lifecycle { eol_components?: number; eos_upcoming?: number; unsupported?: number; unknown_count?: number }
interface Vex { affected_count?: number; under_investigation_count?: number; not_affected_count?: number; fixed_count?: number; unknown_count?: number; vulnerabilities_requiring_action?: number }

export function PortfolioHealth({ health, lifecycle, vex, loading, hasInventory }: {
  health?: Health | null; lifecycle?: Lifecycle | null; vex?: Vex | null; loading: boolean; hasInventory: boolean;
}) {
  const { hasPermission } = useAuth();
  const decisions = [
    {name: 'Affected', value: vex?.affected_count ?? 0, color: '#C0392B'},
    {name: 'Investigating', value: vex?.under_investigation_count ?? 0, color: '#B8860B'},
    {name: 'Not affected', value: vex?.not_affected_count ?? 0, color: '#16845B'},
    {name: 'Fixed', value: vex?.fixed_count ?? 0, color: '#0067B1'},
    {name: 'Unknown', value: vex?.unknown_count ?? 0, color: '#5B7083'},
  ];
  const decisionTotal = decisions.reduce((sum, d) => sum + d.value, 0);
  const metric = (value?: number) => loading ? <Skeleton className="h-5 w-10" /> : value == null ? '—' : value.toLocaleString();
  return <section aria-label="Portfolio health" className="grid min-w-0 gap-4 md:grid-cols-2 xl:grid-cols-3">
    <Surface className="min-w-0 p-5" elevation={1}>
      <h2 className="text-sm font-semibold text-hcl-navy">SBOM Quality &amp; Health</h2>
      <p className="mt-1 text-xs text-hcl-muted">SBOM Completeness · metadata coverage</p>
      {loading ? <Skeleton className="my-5 h-20 w-full" /> : !hasInventory || !Number.isFinite(health?.completeness_score) ? <p className="my-6 text-sm text-hcl-muted">No completeness data available</p> : <div className="my-5 flex items-center gap-5">
        <div className="quality-ring flex h-24 w-24 shrink-0 items-center justify-center rounded-full" style={{ background: `conic-gradient(var(--color-hcl-blue) ${health!.completeness_score!}%, var(--color-surface-muted) 0)` }}>
          <div className="flex h-20 w-20 items-center justify-center rounded-full bg-surface font-metric text-3xl font-bold text-hcl-navy">{Math.round(health!.completeness_score!)}%</div>
        </div>
        <p className="text-xs leading-relaxed text-hcl-muted">Average metadata completeness. Independent of vulnerability severity.</p>
      </div>}
      <dl className="space-y-3 text-xs"><div className="flex justify-between gap-2"><dt>Missing metadata</dt><dd className="font-metric font-semibold">{metric(health?.missing_metadata)}</dd></div><div className="flex justify-between gap-2"><dt>Outdated components</dt><dd className="font-metric font-semibold">{metric(health?.outdated_components)}</dd></div></dl>
      {hasPermission('sbom:read') && <Link href="/sboms" className="mt-4 inline-block rounded text-xs font-medium text-hcl-blue focus-visible:ring-2 focus-visible:ring-hcl-blue">Explore SBOMs →</Link>}
    </Surface>
    <Surface className="min-w-0 p-5" elevation={1}>
      <h2 className="text-sm font-semibold text-hcl-navy">Component Lifecycle</h2>
      <p className="mt-1 text-xs text-hcl-muted">Independent categories may overlap</p>
      <dl className="mt-5 space-y-4">
        {([['End of life', lifecycle?.eol_components], ['Upcoming end of support', lifecycle?.eos_upcoming], ['Unsupported', lifecycle?.unsupported], ['Unknown lifecycle', lifecycle?.unknown_count]] as const).map(([label, value]) => <div key={label} className="flex items-center justify-between gap-3 border-b border-border-subtle pb-2"><dt className="text-xs text-hcl-muted">{label}</dt><dd className="font-metric text-xl font-semibold text-hcl-navy">{metric(value)}</dd></div>)}
      </dl>
      {hasPermission('sbom:read') && <Link href="/sboms" className="mt-4 inline-block rounded text-xs font-medium text-hcl-blue focus-visible:ring-2 focus-visible:ring-hcl-blue">View lifecycle details →</Link>}
    </Surface>
    <Surface className="min-w-0 p-5" elevation={1}>
      <h2 className="text-sm font-semibold text-hcl-navy">VEX Exploitability</h2>
      <p className="mt-1 text-xs text-hcl-muted">Effective product-context decisions</p>
      <div className="mt-4 flex items-center gap-4">
        {!loading && decisionTotal > 0 && <div className="relative h-24 w-24 shrink-0" aria-label={`${decisionTotal} effective VEX contexts`}>
          <ResponsiveContainer width="100%" height={96}><PieChart><Pie data={decisions.filter(d => d.value > 0)} dataKey="value" innerRadius={32} outerRadius={44} isAnimationActive={false}>{decisions.filter(d => d.value > 0).map(d => <Cell key={d.name} fill={d.color} />)}</Pie><Tooltip contentStyle={{background: 'var(--color-surface)', borderColor: 'var(--color-border)', borderRadius: 10}} /></PieChart></ResponsiveContainer>
          <span className="pointer-events-none absolute inset-0 flex items-center justify-center font-metric text-xl font-semibold text-hcl-navy">{decisionTotal}</span>
        </div>}
      <dl className="grid min-w-0 flex-1 grid-cols-2 gap-x-3 gap-y-2">
        {([['Affected', vex?.affected_count], ['Investigating', vex?.under_investigation_count], ['Not affected', vex?.not_affected_count], ['Fixed', vex?.fixed_count], ['Unknown', vex?.unknown_count]] as const).map(([label, value]) => <div key={label}><dt className="text-xs text-hcl-muted">{label}</dt><dd className="font-metric text-xl font-semibold text-hcl-navy">{metric(value)}</dd></div>)}
      </dl>
      </div>
      <div className="mt-4 flex items-center justify-between rounded-lg border border-border bg-surface-muted p-3 text-xs"><span>Requires action</span><strong className="font-metric text-lg">{metric(vex?.vulnerabilities_requiring_action)}</strong></div>
      {hasPermission('vex:read') && <Link href="/vex-investigation" className="mt-3 inline-block rounded text-xs font-medium text-hcl-blue focus-visible:ring-2 focus-visible:ring-hcl-blue">Open investigations →</Link>}
    </Surface>
  </section>;
}

export function runOutcome(run: Pick<AnalysisRun, 'run_status' | 'query_error_count' | 'source'>): string {
  if (run.run_status === 'ERROR') return 'Analysis failed';
  if (run.run_status === 'PARTIAL' || (run.query_error_count ?? 0) > 0 || run.source?.includes('(partial)')) return 'Incomplete coverage';
  return ({ OK: 'Completed · no findings', PASS: 'Completed · no findings', FINDINGS: 'Completed · findings detected', FAIL: 'Completed · findings detected', PENDING: 'Pending', RUNNING: 'Running', INTERRUPTED: 'Interrupted', NO_DATA: 'No data' } as Record<string, string>)[run.run_status] ?? run.run_status;
}

export function DashboardOperations({ scope, tenantId }: { scope: DashboardFilterScope; tenantId: string | null | undefined }) {
  const { hasPermission, user, isPlatformContext } = useAuth();
  const config = useQuery({ queryKey: ["analysis-config", isPlatformContext ? "platform" : tenantId, user?.userId ?? "anonymous", [...(user?.permissions ?? [])].sort().join(",")], queryFn: ({ signal }) => getAnalysisConfig(signal), enabled: !!tenantId && hasPermission("analysis:read"), staleTime: 30_000 });
  const [selected, setSelected] = useState<DashboardPriorityFinding | null>(null);
  const keys = [tenantId, scope.projectId, scope.applicationId, scope.sbomId];
  const findings = useQuery({ queryKey: ['dashboard-priority-findings', ...keys], queryFn: ({ signal }) => getDashboardPriorityFindings(scope, signal), enabled: !!tenantId && hasPermission('analysis:read'), retry: 1 });
  const runs = useQuery({ queryKey: ['dashboard-operational-runs', ...keys], queryFn: ({ signal }) => getDashboardRuns(scope, undefined, 5, signal), enabled: !!tenantId && hasPermission('analysis:read'), retry: 1 });
  if (!hasPermission('analysis:read')) return null;
  const state = (query: { isPending: boolean; isError: boolean; refetch: () => unknown }, empty: boolean) => query.isPending ? <Skeleton className="h-40 w-full" /> : query.isError ? <p role="alert" className="py-6 text-sm text-hcl-muted">Data unavailable. <button className="rounded text-hcl-blue focus-visible:ring-2 focus-visible:ring-hcl-blue" onClick={() => void query.refetch()}>Retry</button></p> : empty ? <p className="py-6 text-sm text-hcl-muted">No records in this scope.</p> : null;
  return <section aria-label="Security operations" className="grid min-w-0 gap-4 xl:grid-cols-[1.38fr_1fr]">
    <Surface className="min-w-0" elevation={1}>
      <SurfaceHeader><h2 className="text-sm font-semibold text-hcl-navy">High-priority findings</h2><Link className="rounded text-xs text-hcl-blue focus-visible:ring-2 focus-visible:ring-hcl-blue" href={dashboardDrilldownUrl('/analysis?tab=vulnerabilities', scope)}>View all →</Link></SurfaceHeader>
      <SurfaceContent>{state(findings, !findings.data?.items.length) ?? <div className="overflow-x-auto"><table className="w-full text-left text-xs"><caption className="sr-only">Current posture, sorted by severity and CVSS score</caption><thead className="text-hcl-muted"><tr><th className="pb-3 font-medium">Vulnerability</th><th className="pb-3 font-medium">Component</th><th className="pb-3 font-medium">Severity</th><th className="pb-3 font-medium">CVSS</th></tr></thead><tbody>{findings.data?.items.map(row => <tr key={row.id} className="border-t border-border-subtle"><td className="py-3 pr-3"><Link className="rounded font-semibold text-hcl-blue focus-visible:ring-2 focus-visible:ring-hcl-blue" href={`/analysis/${row.analysis_run_id}`}>{row.vuln_id}</Link>{config.data?.cve_modal_enabled !== false && <button aria-label={`View details for ${row.vuln_id} on ${row.component_name ?? "unmapped component"}`} onClick={() => setSelected(row)} className="mt-1 block rounded text-[10px] text-hcl-muted hover:text-hcl-blue focus-visible:ring-2 focus-visible:ring-hcl-blue">Details →</button>}</td><td className="py-3 pr-3"><span className="block max-w-48 truncate" title={row.component_name ?? undefined}>{row.component_name ?? 'Unmapped component'}</span><span className="text-hcl-muted">{row.component_version ?? 'Version unknown'}</span></td><td className="py-3 pr-3">{row.severity ?? 'Unknown'}</td><td className="py-3 font-metric">{row.score ?? '—'}</td></tr>)}</tbody></table></div>}</SurfaceContent>
    </Surface>
    <Surface className="min-w-0" elevation={1}>
      <SurfaceHeader><h2 className="text-sm font-semibold text-hcl-navy">Recent analysis runs</h2><Link href={dashboardDrilldownUrl('/analysis', scope)} className="rounded text-xs text-hcl-blue focus-visible:ring-2 focus-visible:ring-hcl-blue">View all →</Link></SurfaceHeader>
      <SurfaceContent>{state(runs, !runs.data?.length) ?? <ul className="divide-y divide-border-subtle">{runs.data?.map(run => <li key={run.id} className="py-3 first:pt-0"><div className="flex items-center justify-between gap-3"><Link href={`/analysis/${run.id}`} className="truncate rounded text-xs font-semibold text-hcl-blue focus-visible:ring-2 focus-visible:ring-hcl-blue" title={run.sbom_name ?? undefined}>{run.sbom_name ?? `Analysis #${run.id}`}</Link><span className="shrink-0 text-[10px] text-hcl-muted">{run.completed_on ? formatDate(run.completed_on) : 'In progress'}</span></div><div className="mt-1 flex justify-between gap-2 text-xs text-hcl-muted"><span>{runOutcome(run)}</span><span className="font-metric">{run.total_findings ?? '—'} findings</span></div></li>)}</ul>}</SurfaceContent>
    </Surface>
    <CveDetailDialog cveId={selected?.vuln_id ?? null} scanId={selected?.component_id ? selected.analysis_run_id : null} componentId={selected?.component_id ?? null} findingId={selected?.id ?? null} open={!!selected} onOpenChange={open => { if (!open) setSelected(null); }} seed={null} />
  </section>;
}
