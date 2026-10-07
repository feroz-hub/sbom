'use client';
import { useEffect, useRef, useState } from 'react';
import { ChevronLeft, ChevronRight, CheckCircle2, CircleAlert, PanelLeftClose, Copy, LocateFixed, Search } from 'lucide-react';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import type { RepairIssue } from '@/lib/repairIssuePresentation';
import { stageLabel } from '@/lib/sbomValidation';

type Filter = 'all' | 'errors' | 'warnings' | 'info' | 'auto' | 'manual';
export function RepairIssueNavigator({ issues, selectedKey, onSelect, onNavigate, canNavigate, passed, errorCount, warningCount, truncated, lastValidated, busy, onSafeRepair, currentValue, importReady, importHint, onViewReport, onHide }: {
  issues: RepairIssue[]; selectedKey: string | null; onSelect: (issue: RepairIssue) => void;
  onNavigate: (issue: RepairIssue) => void; canNavigate: (issue: RepairIssue) => boolean;
  onHide?: () => void; importReady: boolean; importHint: string; onViewReport: () => void;
  passed: boolean; errorCount: number; warningCount: number; truncated?: boolean;
  lastValidated?: string | null; currentValue?: string; busy: boolean; onSafeRepair?: () => void;
}) {
  const listRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const list = listRef.current; const selected = list?.querySelector<HTMLElement>('[data-selected="true"]');
    if (!list || !selected) return;
    const offset = selected.getBoundingClientRect().top - list.getBoundingClientRect().top;
    if (offset < 0 || offset + selected.offsetHeight > list.clientHeight) list.scrollTop += offset - 12;
  }, [selectedKey]);
  const [filter, setFilter] = useState<Filter>('all');
  const [search, setSearch] = useState('');
  const [copyMessage, setCopyMessage] = useState('');
  const infoCount = issues.filter(issue => issue.entry.severity === 'info').length;
  const automatic = issues.filter(issue => issue.classification === 'AUTO_FIX').length;
  const manual = issues.filter(issue => issue.classification === 'MANUAL_ONLY').length;
  const visible = issues.filter(issue => (filter === 'all' || filter === 'errors' && issue.entry.severity === 'error' || filter === 'warnings' && issue.entry.severity === 'warning' || filter === 'info' && issue.entry.severity === 'info' || filter === 'auto' && issue.classification === 'AUTO_FIX' || filter === 'manual' && issue.classification === 'MANUAL_ONLY') && `${issue.entry.code} ${issue.title} ${issue.location} ${issue.entry.message}`.toLowerCase().includes(search.toLowerCase()));
  const selectedIndex = visible.findIndex(issue => issue.key === selectedKey);
  function move(direction: number) {
    const index = selectedIndex < 0 ? 0 : selectedIndex + direction;
    if (visible[index]) { onSelect(visible[index]); if (canNavigate(visible[index])) onNavigate(visible[index]); }
  }
  async function copy(path: string) {
    try { await navigator.clipboard.writeText(path); setCopyMessage('Issue path copied.'); }
    catch { setCopyMessage('Copy is unavailable. Select the path in Technical details to copy it.'); }
  }
  return <section aria-label="Validation Issues" className="flex h-full min-h-0 min-w-0 overflow-hidden flex-col rounded-xl border border-border bg-surface" onKeyDown={event => {
    if (event.key === 'Escape' && window.matchMedia('(max-width: 767px)').matches && onHide) { event.preventDefault(); event.stopPropagation(); onHide(); return; }
    if (event.altKey && ['ArrowDown', 'ArrowUp'].includes(event.key)) { event.preventDefault(); move(event.key === 'ArrowDown' ? 1 : -1); }
  }}>
    <div className="shrink-0 space-y-2 border-b border-border p-3">
      <div className="flex items-center justify-between gap-2"><h2 className="text-sm font-semibold text-hcl-navy">Validation Issues</h2>{onHide && <Button size="icon" variant="ghost" className="h-7 w-7" aria-label="Hide validation issues" title="Hide issues" onClick={onHide}><PanelLeftClose className="h-4 w-4" /></Button>}</div>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs"><span className={`inline-flex items-center gap-1 font-medium ${passed ? 'text-emerald-700' : errorCount ? 'text-red-700' : 'text-hcl-muted'}`}>{passed ? <CheckCircle2 className="h-3.5 w-3.5" /> : <CircleAlert className="h-3.5 w-3.5" />}{passed ? 'Passed' : errorCount ? 'Failed' : 'Awaiting validation'}</span><span className="text-hcl-muted">{errorCount} {errorCount === 1 ? 'error' : 'errors'} · {warningCount} {warningCount === 1 ? 'warning' : 'warnings'}{infoCount > 0 ? ` · ${infoCount} info` : ''}</span></div>
      <div role="group" aria-label="Filter validation issues" className="flex flex-wrap gap-1">{([
        ['all', 'All', issues.length], ['errors', 'Errors', errorCount], ['warnings', 'Warnings', warningCount],
        ...(infoCount ? [['info', 'Info', infoCount]] : []), ...(automatic ? [['auto', 'Auto-fixable', automatic]] : []), ...(manual ? [['manual', 'Manual review', manual]] : []),
      ] as [Filter, string, number][]).map(([value, label, count]) => <button key={value} aria-pressed={filter === value} onClick={() => setFilter(value)} className={`rounded-md border px-2 py-1 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/50 ${filter === value ? 'border-hcl-blue/30 bg-blue-50 text-hcl-blue' : 'border-border text-hcl-muted hover:bg-surface-muted'}`}>{label} {count}</button>)}</div>
      <div className="relative"><Search className="pointer-events-none absolute left-2.5 top-2 h-3.5 w-3.5 text-hcl-muted" aria-hidden /><input aria-label="Search validation issues" placeholder="Search issues…" value={search} onChange={event => setSearch(event.target.value)} className="h-8 w-full min-w-0 rounded-lg border border-border bg-surface pl-8 pr-2 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/30" /></div>
      <div className="flex items-center justify-between gap-1"><Button aria-label="Previous issue" title="Previous issue (Alt + ↑)" aria-keyshortcuts="Alt+ArrowUp" size="sm" variant="ghost" disabled={selectedIndex <= 0} onClick={() => move(-1)}><ChevronLeft className="h-3 w-3" />Previous</Button><span aria-live="polite" className="text-xs text-hcl-muted">{selectedIndex < 0 ? 0 : selectedIndex + 1} / {visible.length}</span><Button aria-label="Next issue" title="Next issue (Alt + ↓)" aria-keyshortcuts="Alt+ArrowDown" size="sm" variant="ghost" disabled={!visible.length || selectedIndex >= visible.length - 1} onClick={() => move(1)}>Next<ChevronRight className="h-3 w-3" /></Button></div>
    </div>
    <div ref={listRef} className="min-h-0 flex-1 space-y-2 overflow-y-auto overflow-x-hidden p-3 xl:p-4" aria-label="Issue list">
      {!visible.length && <div className="py-2 text-sm text-hcl-muted">{issues.length ? 'No issues match this filter.' : passed ? <><p className="font-medium text-emerald-700">✓ No validation issues</p><p className="mt-1 text-xs">{importReady ? 'This SBOM passed validation and is ready to import.' : importHint}</p><Button size="sm" variant="ghost" onClick={onViewReport}>View validation report</Button></> : 'No issue details are available. Revalidate to refresh the report.'}</div>}
      {visible.map((issue, index) => <article data-selected={selectedKey === issue.key} key={issue.key} aria-label={`${issue.code} ${issue.title}`} className={`min-w-0 rounded-md border border-border border-l-[3px] px-3 py-2 transition-colors ${selectedKey === issue.key ? 'border-l-hcl-blue bg-blue-50/60' : 'border-l-transparent bg-surface'}`}>
        <button className="block w-full min-w-0 rounded text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/50" aria-current={selectedKey === issue.key ? 'true' : undefined} aria-pressed={selectedKey === issue.key} onClick={() => { onSelect(issue); if (canNavigate(issue)) onNavigate(issue); }}>
          <span className="flex items-center justify-between gap-2"><Badge variant={issue.entry.severity === 'error' ? 'error' : issue.entry.severity === 'warning' ? 'warning' : 'info'}>{issue.entry.severity.toUpperCase()}</Badge><span className="text-[11px] text-hcl-muted">{index + 1} / {visible.length}</span></span>
          <span className="mt-1 block text-sm font-semibold text-hcl-navy">{issue.title}</span>
          <span title={issue.entry.code} className="mt-0.5 block truncate font-mono text-[11px] text-hcl-muted">{issue.code.match(/^[EWI]\d{3}$/) ? `SBOM_VAL_${issue.code}` : issue.code}</span>
          <span className="mt-1 block text-[11px] text-hcl-muted">Location</span><span title={issue.location} className="block truncate font-mono text-xs text-foreground">{issue.location}</span><span className="mt-1 block [overflow-wrap:anywhere] text-xs leading-relaxed text-hcl-muted">{issue.explanation}</span>
        </button>
        <div className="mt-2 flex flex-wrap gap-2">{canNavigate(issue) ? <Button size="sm" variant="secondary" onClick={() => { onSelect(issue); onNavigate(issue); }}><LocateFixed className="h-3.5 w-3.5" />Go to location →</Button> : <Button size="sm" variant="secondary" onClick={() => { onSelect(issue); void copy(issue.location); }}><Copy className="h-3.5 w-3.5" />Copy path</Button>}{issue.classification === 'AUTO_FIX' && onSafeRepair && <Button size="sm" variant="ghost" disabled={busy} onClick={onSafeRepair}>Review safe repair</Button>}</div>
        <details className="mt-2 min-w-0 text-xs text-hcl-muted" onToggle={event => { if (event.currentTarget.open) onSelect(issue); }}><summary className="cursor-pointer font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/50">Details{issue.classification === 'MANUAL_ONLY' && <span className="ml-2 text-[10px]">MANUAL REVIEW</span>}</summary>
          <dl className="mt-2 space-y-2 [overflow-wrap:anywhere]"><div><dt className="font-medium">Issue</dt><dd>{issue.title}</dd></div><div><dt className="font-medium">Code</dt><dd className="font-mono">{issue.entry.code}</dd></div><div><dt className="font-medium">Location</dt><dd className="font-mono select-text">{issue.location}</dd><Button size="sm" variant="ghost" onClick={() => void copy(issue.location)}><Copy className="h-3 w-3" />Copy location</Button></div><div><dt className="font-medium">Description</dt><dd className="whitespace-pre-wrap">{issue.explanation}</dd></div>{issue.guidance && <div><dt className="font-medium">Repair guidance</dt><dd className="whitespace-pre-wrap">{issue.guidance}</dd></div>}{issue.classification === 'MANUAL_ONLY' && <p>This issue cannot be safely repaired automatically.</p>}{currentValue !== undefined && selectedKey === issue.key && <div><dt className="font-medium">Current value</dt><dd className="font-mono whitespace-pre-wrap">{currentValue}</dd></div>}</dl>
          <details className="mt-3"><summary className="cursor-pointer font-medium">Technical details</summary><div className="mt-2 space-y-2 [overflow-wrap:anywhere]"><p className="font-mono">{issue.entry.code}</p><p className="font-mono select-text">{issue.location}</p><p className="whitespace-pre-wrap">{issue.entry.message}</p><p>{stageLabel(issue.entry.stage)}{issue.entry.line ? ` · Validator line ${issue.entry.line}` : ''}</p>{issue.entry.spec_reference && <p>{issue.entry.spec_reference}</p>}</div></details>
        </details>
      </article>)}
      {truncated && <p className="text-xs text-amber-800">This report is limited. Revalidation may reveal additional issues.</p>}
    </div>
    <div className="shrink-0 border-t border-border px-3 py-2 text-xs"><p className={`font-medium ${errorCount ? 'text-red-700' : passed ? 'text-emerald-700' : 'text-hcl-muted'}`}>{errorCount ? `✕ ${errorCount} blocking ${errorCount === 1 ? 'error remains' : 'errors remain'}` : passed ? issues.length ? '✓ No blocking errors' : '✓ No validation issues' : 'Validation required'}</p><p className="mt-1 text-hcl-muted">{importReady ? issues.length ? 'This SBOM can be imported. Review remaining findings if needed.' : 'This SBOM is ready to import.' : importHint}</p><p className="mt-2 text-[10px] text-hcl-muted">Alt + ↑ / ↓ moves between issues.{lastValidated ? ` Last validated: ${lastValidated}` : ''}</p><p role="status" aria-live="polite">{copyMessage}</p></div>
  </section>;
}
