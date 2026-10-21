'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useAuth } from '@/hooks/useAuth';
import { getVexVersionComparison } from '@/lib/api';
import { Alert } from '@/components/ui/Alert';
import { Button } from '@/components/ui/Button';
import { Select } from '@/components/ui/Select';
import { CveDetailDialog, type CveRowSeed } from '@/components/vulnerabilities/CveDetailDialog';
import type { VexComparisonContext } from '@/types';

export function VexVersionComparisonPanel({sbomId}: {sbomId: (string | number)}) {
  const {activeTenantId} = useAuth();
  const [open, setOpen] = useState(false);
  const [category, setCategory] = useState('ALL');
  const [selection, setSelection] = useState<VexComparisonContext | null>(null);
  const query = useQuery({
    queryKey: ['vex-version-comparison', activeTenantId, sbomId],
    queryFn: ({signal}) => getVexVersionComparison(sbomId, signal), enabled: open && !!activeTenantId,
  });
  const data = query.data;
  const seed: CveRowSeed | null = selection ? {vuln_id: selection.vulnerability_id, cve_aliases: [], severity: null,
    score: null, cvss_version: null, in_kev: false, epss: null, epss_percentile: null,
    component_name: selection.component_name, component_version: selection.component_version, source: 'Stored analysis'} : null;
  return <section aria-label="Version comparison" className="min-w-0 break-words space-y-3 rounded-lg border border-border bg-surface p-4">
    <Button variant="outline" onClick={() => setOpen(value => !value)}>Compare versions</Button>
    {open && query.isPending && <p role="status">Loading version comparison…</p>}
    {open && query.isError && <Alert variant="warning">Version comparison unavailable. Both versions require successful analyses and a declared predecessor. Try again after analysis completes.</Alert>}
    {open && data && <>
      <h2 className="font-semibold">Previous: {data.previous_version} → Current: {data.current_version}</h2>
      <p className="text-xs text-hcl-muted">Distinct vulnerability/component/version contexts in analysis runs {data.previous_run_id} and {data.current_run_id}. No longer observed does not mean Fixed.</p>
      <dl className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {([['Previous findings',data.previous_findings],['Current findings',data.current_findings],['Still detected',data.still_detected],['New',data.new],['No longer observed',data.no_longer_observed],['Unresolved comparison',data.unresolved_comparison]] as const).map(([label,value]) => <div key={label}><dt className="text-xs">{label}</dt><dd className="text-lg font-semibold">{value}</dd></div>)}
      </dl>
      {data.limitations.map(message => <Alert variant="warning" key={message}>{message}</Alert>)}
      <Select label="Comparison category" value={category} onChange={event => setCategory(event.target.value)}>
        {['ALL','NEW','STILL_DETECTED','NO_LONGER_OBSERVED','UNRESOLVED_COMPARISON'].map(value => <option key={value} value={value}>{value === 'ALL' ? 'All changes' : value.toLowerCase().replaceAll('_',' ')}</option>)}
      </Select>
      <div className="max-h-96 space-y-2 overflow-y-auto">
        {data.items.filter(item => category === 'ALL' || item.category === category).map((item,index) => <article key={index} className="rounded border border-border p-3 text-sm">
          <p className="font-semibold">{(item.current ?? item.previous)?.vulnerability_id} · {item.category.toLowerCase().replaceAll('_',' ')}</p>
          {(['previous','current'] as const).map(side => item[side] && <div key={side} className="flex flex-wrap items-center gap-2">
            <span>{side}: {item[side]!.component_name} {item[side]!.component_version}</span>
            <Button variant="ghost" size="sm" onClick={() => setSelection(item[side])}>Open {side} details</Button>
            <a className="text-hcl-blue underline" href={`/vex-investigation?version_scope=all&sbom_id=${item[side]!.sbom_id}&q=${encodeURIComponent(item[side]!.vulnerability_id)}`}>View {side} investigations</a>
          </div>)}
          {item.current_component && <p>Current component: {item.current_component.name} {item.current_component.version} · Not detected in the current analysis.</p>}
          <p>{item.reason}</p>
        </article>)}
      </div>
    </>}
    {selection && <CveDetailDialog open cveId={selection.vulnerability_id} seed={seed} scanId={selection.analysis_run_id} componentId={selection.component_id ?? undefined} onOpenChange={open => { if (!open) setSelection(null); }} />}
  </section>;
}
