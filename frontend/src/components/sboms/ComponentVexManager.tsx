'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getComponentVulnerabilities, getVexOverrideHistory } from '@/lib/api';
import type { SBOMComponent, VexStatement } from '@/types';
import { Dialog, DialogBody } from '@/components/ui/Dialog';
import { Button } from '@/components/ui/Button';

export function ComponentVexManager({ sbomId, component, canEdit, onClose, onDecision }: {
  sbomId: number; component: SBOMComponent; canEdit: boolean; onClose: () => void;
  onDecision: (vulnerability: string, statement?: VexStatement, manual?: boolean) => void;
}) {
  const [search, setSearch] = useState('');
  const [historyPair, setHistoryPair] = useState<string | null>(null);
  const list = useQuery({
    queryKey: ['component-vulnerabilities', sbomId, component.id],
    queryFn: ({ signal }) => getComponentVulnerabilities(sbomId, component.id, signal),
  });
  const history = useQuery({
    queryKey: ['vex-pair-history', sbomId, component.id, historyPair],
    queryFn: ({ signal }) => getVexOverrideHistory(component.id, historyPair!, signal, sbomId),
    enabled: Boolean(historyPair),
  });
  const rows = (list.data?.vulnerabilities ?? []).filter(row => row.vulnerability_id.toLowerCase().includes(search.toLowerCase()));
  return <>
    <Dialog open={!historyPair} onClose={onClose} title={`Manage VEX — ${component.name} @ ${component.version ?? 'unknown'}`} maxWidth="2xl">
      <DialogBody>
        <p className="mb-3 text-sm">SBOM #{sbomId} · Component #{component.id}. Each vulnerability has its own decision.</p>
        <div className="mb-4 flex items-center gap-3">
          <input aria-label="Search vulnerabilities" placeholder="Search CVE, GHSA or vendor identifier" value={search}
            onChange={event => setSearch(event.target.value)} className="w-full rounded border p-2" />
          {canEdit && <Button onClick={() => onDecision('', undefined, true)}>Add Vulnerability Manually</Button>}
        </div>
        {list.isPending ? <p>Loading component vulnerabilities…</p> : list.isError ?
          <p role="alert">Could not load vulnerabilities. <button onClick={() => list.refetch()}>Retry</button></p> :
          <div className="overflow-x-auto"><table className="w-full text-left text-sm">
            <thead><tr>{['Vulnerability', 'Severity', 'Finding / match information', 'Current effective VEX status', 'VEX source', 'Last updated', 'Actions'].map(label => <th className="p-2" key={label}>{label}</th>)}</tr></thead>
            <tbody>{rows.map(row => <tr className="border-t" key={row.vulnerability_id}>
              <td className="p-2 font-mono">{row.vulnerability_id}</td><td className="p-2">{row.severity ?? 'Unknown'}</td>
              <td className="p-2">{row.findings.length ? <details><summary>{row.findings.length} finding(s)</summary>
                {row.findings.map(f => <p key={f.id}>Run #{f.run_id} · {f.source ?? 'Unknown source'} · {f.match_reason ?? 'No match detail'} {f.matched_range ?? ''}</p>)}
              </details> : 'No detected finding; VEX evidence only'}</td>
              <td className="p-2">{row.current_decision?.status ?? 'No decision'}</td>
              <td className="p-2">{row.current_decision?.source_name ?? '—'}</td>
              <td className="p-2">{row.current_decision?.created_at ?? '—'}</td>
              <td className="p-2">{canEdit && <Button size="sm" onClick={() => onDecision(row.vulnerability_id, row.current_decision ?? undefined)}>
                {!row.current_decision ? 'Add Decision' : row.current_decision.source_name === 'Manual VEX Override' ? 'Edit' : 'Override'}
              </Button>} <Button size="sm" variant="ghost" onClick={() => setHistoryPair(row.vulnerability_id)}>History</Button></td>
            </tr>)}</tbody>
          </table>{!rows.length && <p className="py-4">No matching vulnerabilities for this component.</p>}</div>}
      </DialogBody>
    </Dialog>
    <Dialog open={Boolean(historyPair)} onClose={() => setHistoryPair(null)} title={`VEX History — ${historyPair ?? ''}`} maxWidth="xl">
      <DialogBody>
        <p>{component.name} @ {component.version} · SBOM #{sbomId}</p>
        {history.isPending ? <p>Loading history…</p> : history.isError ? <p role="alert">Could not load history.</p> : <>
          <h3 className="mt-3 font-semibold">Current VEX Decision</h3>
          <p>{history.data?.current_decision?.status ?? 'No decision'} · {history.data?.current_decision?.source_name ?? '—'}</p>
          <h3 className="mt-3 font-semibold">History</h3>
          {(history.data?.statements ?? []).map(row => <article key={row.id} className="my-2 rounded border p-3">
            <p>{row.status} · {row.source_name} · {row.created_at}{row.id === history.data?.current_decision?.id ? ' · Current' : ''}</p>
            <p>{row.justification}</p><p>{row.impact_statement}</p><p>{row.action_statement}</p>
            <p>{row.fixed_version && `Fixed version: ${row.fixed_version}`}</p><p>{row.mitigation}</p><p>{row.source_url}</p>
            {history.data?.history.filter(a => a.new_value?.id === row.id).map(a => <p key={a.id}>{a.changed_by}: {a.reason}</p>)}
          </article>)}
          {!history.data?.statements?.length && <p>No previous decisions for this pair.</p>}
        </>}
      </DialogBody>
    </Dialog>
  </>;
}
