'use client';

import Link from 'next/link';
import { useEffect, useRef, useState } from 'react';
import { ArrowDown, ArrowUp, ArrowUpDown, MoreHorizontal, X } from 'lucide-react';
import { LifecycleBadge, ProvenanceBadge, RiskBadge } from './AdvisorBadges';
import { STATUS_LABELS, formatTimestamp } from './labels';
import { Button } from '@/components/ui/Button';
import { TableBody, Td } from '@/components/ui/Table';
import type { AdvisorComponent, AdvisorSortField } from '@/types/componentAdvisor';
import styles from './ComponentGrid.module.css';

type Props = {
  rows: AdvisorComponent[]; loading: boolean; error: boolean; scopeQuery: string;
  sortBy: AdvisorSortField; sortOrder: 'asc' | 'desc';
  onSort: (field: AdvisorSortField) => void; onClear: () => void;
};

function Severity({ row }: { row: AdvisorComponent }) {
  const counts = row.risk.actionable_severity_counts;
  return <div><div className={styles.severity}>{(['critical', 'high', 'medium', 'low'] as const).map((key) =>
    <span key={key} aria-label={`${key}: ${counts[key]}`} className={counts[key] ? styles[key] : styles.zero}>{key[0].toUpperCase()} {counts[key]}</span>)}
    {counts.unknown > 0 && <span aria-label={`Unknown severity: ${counts.unknown}`}>U {counts.unknown}</span>}
  </div><span className={styles.secondary}>CVSS max {row.risk.cvss.max_score ?? '—'}</span></div>;
}
function Actionable({ row }: { row: AdvisorComponent }) {
  return <span className={row.risk.actionable_vulnerability_count ? styles.actionable : styles.secondary}><strong>{row.risk.actionable_vulnerability_count}</strong> actionable</span>;
}
function Lifecycle({ row }: { row: AdvisorComponent }) {
  const date = row.lifecycle.effective_date;
  // Format only the supplied effective date; do not infer another lifecycle milestone.
  const parsed = date ? new Date(date) : null;
  return <div><LifecycleBadge bucket={row.lifecycle.bucket} />{date && <time className={styles.secondary} dateTime={date}>{parsed && !Number.isNaN(parsed.getTime()) ? parsed.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' }) : date}</time>}</div>;
}
function Decision({ row, query }: { row: AdvisorComponent; query: string }) {
  if (row.recommendation.status === 'NOT_EVALUATED') return <span className={styles.secondary}>—</span>;
  const label = STATUS_LABELS[row.recommendation.status] ?? row.recommendation.status;
  return row.recommendation.id ? <Link className={styles.link} href={`/component-advisor/recommendations/${row.recommendation.id}${query}`}>{label}</Link> : <span>{label}</span>;
}
function attention(row: AdvisorComponent) {
  return row.risk.classification === 'CRITICAL' ? 'critical' : row.risk.classification === 'HIGH' ? 'high' : row.lifecycle.bucket === 'EOL' ? 'eol' : undefined;
}

export function ComponentGrid({ rows, loading, error, scopeQuery, sortBy, sortOrder, onSort, onClear }: Props) {
  const [selected, setSelected] = useState<AdvisorComponent | null>(null);
  const dialog = useRef<HTMLDialogElement>(null);
  const opener = useRef<HTMLElement | null>(null);
  useEffect(() => { if (selected && !dialog.current?.open) dialog.current?.showModal(); }, [selected]);
  function open(row: AdvisorComponent, trigger: HTMLElement) { opener.current = trigger; setSelected(row); }
  function close() { dialog.current?.close(); setSelected(null); opener.current?.focus(); }
  function header(label: string, field?: AdvisorSortField, frozen = false) {
    const Icon = sortBy === field ? (sortOrder === 'asc' ? ArrowUp : ArrowDown) : ArrowUpDown;
    return <th scope="col" className={frozen ? styles.frozen : undefined} aria-sort={field ? sortBy === field ? sortOrder === 'asc' ? 'ascending' : 'descending' : 'none' : undefined}>
      {field ? <button type="button" aria-label={`Sort by ${label}`} onClick={() => onSort(field)}>{label}<Icon size={13} aria-hidden /></button> : label}</th>;
  }
  const empty = <div className={styles.empty}><p>No components match the current filters.</p><Button variant="secondary" onClick={onClear}>Clear filters</Button></div>;
  return <div className={styles.grid}>
    <div className={styles.desktop} role="region" aria-label="Component versions" tabIndex={0} aria-busy={loading}>
      <table><caption className="sr-only">Component versions</caption>
        <colgroup>{[170, 90, 240, 210, 120, 170, 85, 85, 85, 180, 150, 56].map((width, i) => <col key={i} style={{ width }} />)}</colgroup>
        <thead><tr className={styles.groups}><th scope="colgroup" colSpan={3}>Identity</th><th scope="colgroup" colSpan={3}>Risk</th><th scope="colgroup" colSpan={3}>Usage</th><th scope="colgroup">Lifecycle</th><th scope="colgroup" colSpan={2}>Decision</th></tr>
          <tr>{header('Component', 'name', true)}{header('Version')}{header('Supplier / ecosystem')}{header('Classification', 'risk')}{header('Actionable', 'actionable')}{header('Severity / CVSS')}{header('SBOMs', 'occurrences')}{header('Projects')}{header('Products', 'products')}{header('Status')}{header('Recommendation')}{header('Actions')}</tr>
        </thead>
        <TableBody>{loading ? Array.from({ length: 6 }, (_, i) => <tr key={i} aria-hidden>{Array.from({ length: 12 }, (_, j) => <td key={j}><div className={styles.skeleton} /></td>)}</tr>) : error ? null : !rows.length ? <tr><td colSpan={12}>{empty}</td></tr> : rows.map(row => <tr key={row.canonical_key} data-attention={attention(row)}>
          <Td className={styles.frozen}><button className={styles.name} onClick={e => open(row, e.currentTarget)}>{row.name}</button></Td>
          <Td><span className={styles.secondary}>{row.version ?? '—'}</span></Td>
          <Td><span className={styles.supplier}>{row.supplier ?? '—'}</span><span className={styles.ecosystem}>{row.ecosystem ?? 'Unknown ecosystem'}</span>{row.purl && <span tabIndex={0} className={styles.purl}
            onKeyDown={e => { if (e.key === 'Escape') e.currentTarget.dataset.dismissed = 'true'; }}
            onFocus={e => { delete e.currentTarget.dataset.dismissed; }}
            onMouseEnter={e => { delete e.currentTarget.dataset.dismissed; }} aria-label={`PURL: ${row.purl}`}><span className={styles.truncate}>{row.purl}</span><span role="tooltip" className={styles.tooltip}>{row.purl}</span></span>}</Td>
          <Td><RiskBadge classification={row.risk.classification} />{row.risk.review_reasons.length > 0 && <span className={styles.secondary}>Needs review: {row.risk.review_reasons.length} reason(s)</span>}</Td>
          <Td><Actionable row={row} /></Td><Td><Severity row={row} /></Td>
          <Td className={styles.numeric}>{row.usage.active_sbom_occurrences}</Td><Td className={styles.numeric}>{row.usage.project_count}</Td><Td className={styles.numeric}>{row.usage.product_count}</Td>
          <Td><Lifecycle row={row} /></Td><Td><Decision row={row} query={scopeQuery} /></Td>
          <Td><button className={styles.action} aria-label={`View details for ${row.name} ${row.version ?? ''}`} onClick={e => open(row, e.currentTarget)}><MoreHorizontal size={20} aria-hidden /></button></Td>
        </tr>)}</TableBody>
      </table>
    </div>
    <div className={styles.mobile} aria-busy={loading}>{loading ? Array.from({ length: 4 }, (_, i) => <div key={i} className={styles.skeleton} />) : error ? null : !rows.length ? empty : rows.map(row => <article key={row.canonical_key} data-attention={attention(row)}>
      <button className={styles.name} onClick={e => open(row, e.currentTarget)}>{row.name}</button><span className={styles.secondary}>{row.version ?? '—'}</span>
      <RiskBadge classification={row.risk.classification} /><div className={styles.mobileRisk}><Actionable row={row} /><Severity row={row} /></div>
      <p className={styles.secondary}>{row.usage.active_sbom_occurrences} SBOMs · {row.usage.project_count} Projects · {row.usage.product_count} Products</p><Lifecycle row={row} />
      <div className={styles.mobileRisk}><Decision row={row} query={scopeQuery} /><button className={styles.link} onClick={e => open(row, e.currentTarget)}>View details</button></div>
    </article>)}</div>
    <dialog ref={dialog} className={styles.drawer} aria-labelledby="component-drawer-title" onCancel={e => { e.preventDefault(); close(); }} onClick={e => { if (e.target === e.currentTarget) close(); }}>
      {selected && <><div className={styles.drawerHeading}><h2 id="component-drawer-title">Component details</h2><button autoFocus className={styles.action} onClick={close} aria-label="Close component details"><X size={20} /></button></div>
        <h3>{selected.name} <span className={styles.secondary}>{selected.version}</span></h3>
        <section><h4>Identity</h4><dl>{[['Name', selected.name], ['Version', selected.version], ['Supplier', selected.supplier], ['Ecosystem', selected.ecosystem], ['PURL', selected.purl], ['CPE', selected.cpe]].map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value ?? '—'}</dd></div>)}</dl></section>
        <section><h4>Risk</h4><RiskBadge classification={selected.risk.classification} /><p><Actionable row={selected} /></p><Severity row={selected} />{selected.risk.review_reasons.length > 0 && <p className={styles.secondary}>Review reasons: {selected.risk.review_reasons.join(', ')}</p>}</section>
        <section><h4>Usage</h4><p>{selected.usage.active_sbom_occurrences} active SBOM occurrences · {selected.usage.sbom_count} distinct SBOMs · {selected.usage.project_count} Projects · {selected.usage.product_count} Products</p></section>
        <section><h4>Lifecycle</h4><Lifecycle row={selected} /><p className={styles.secondary}>Source: {selected.lifecycle.source ?? 'Not available'}</p></section>
        <section><h4>Decision</h4><Decision row={selected} query={scopeQuery} />{selected.purpose.technology_category && <p>{selected.purpose.technology_category.value} <ProvenanceBadge field={selected.purpose.technology_category} /></p>}<p className={styles.secondary}>Latest analysis: {formatTimestamp(selected.freshness.latest_analysis_at)}</p></section>
        <Link className={styles.link} href={`/component-advisor/components/${selected.canonical_key}${scopeQuery}`}>Open full component details →</Link>
      </>}
    </dialog>
  </div>;
}
