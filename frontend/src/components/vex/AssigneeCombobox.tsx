'use client';

import { useEffect, useId, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { ChevronDown } from 'lucide-react';
import type { VexInvestigationCapabilities } from '@/types';

type Candidate = VexInvestigationCapabilities['candidates'][number];

export function AssigneeIdentity({ user, isSelf = false }: { user: Omit<Candidate, 'id'>; isSelf?: boolean }) {
  return <div className="flex items-center gap-3 text-left">
    <span aria-hidden="true" className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-hcl-blue/10 text-xs font-semibold text-hcl-blue">
      {user.label.split(/\s+/).slice(0, 2).map(part => part[0]).join('').toUpperCase()}
    </span>
    <div className="min-w-0 flex-1">
      <div className="text-sm font-medium">{user.label}{isSelf ? ' (You)' : ''}</div>
      {user.email ? <div className="break-all text-xs text-hcl-muted">{user.email}</div> : null}
      <div className="mt-1 flex flex-wrap gap-1">{user.roles.filter(role => ['SECURITY_ANALYST', 'DEVELOPER'].includes(role)).map(role =>
        <span key={role} className="rounded bg-surface-muted px-1.5 py-0.5 text-[10px] font-medium">{role.replaceAll('_', ' ')}</span>)}
      </div>
    </div>
  </div>;
}

/** Uses only the server-authorized candidates attached to this investigation. */
export function AssigneeCombobox({ candidates, selected, onSelect, disabled = false,
  label = 'Assignee', compact = false, onSearch, loading = false, error = false, onRetry, onLoadMore, selectedLabel,
}: {
  candidates: Candidate[];
  selected: string;
  onSelect: (id: string) => void;
  disabled?: boolean;
  label?: string;
  compact?: boolean;
  onSearch?: (query: string) => void;
  loading?: boolean;
  error?: boolean;
  onRetry?: () => void;
  onLoadMore?: () => void;
  selectedLabel?: string;
}) {
  const id = useId();
  const input = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState('');
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const [position, setPosition] = useState<React.CSSProperties>({});
  useEffect(() => {
    if (!open) return;
    const place = () => {
      const rect = input.current?.getBoundingClientRect();
      if (!rect) return;
      if (rect.bottom < 0 || rect.top > window.innerHeight) { setOpen(false); return; }
      const below = window.innerHeight - rect.bottom - 12;
      const above = below < 160 && rect.top > below;
      const width = Math.min(rect.width, window.innerWidth - 16);
      setPosition({ position: 'fixed', left: Math.max(8, Math.min(rect.left, window.innerWidth - width - 8)), width,
        top: above ? undefined : rect.bottom + 4, bottom: above ? window.innerHeight - rect.top + 4 : undefined,
        maxHeight: Math.max(64, Math.min(256, above ? rect.top - 12 : below)) });
    };
    place();
    window.addEventListener('scroll', place, true);
    window.addEventListener('resize', place);
    return () => { window.removeEventListener('scroll', place, true); window.removeEventListener('resize', place); };
  }, [open]);
  // Show immediate matches from the loaded page while optional server search
  // discovers additional pages; never fetch a platform-wide user directory.
  const matches = candidates.filter(user => `${user.label} ${user.email ?? ''}`.toLowerCase().includes(query.trim().toLowerCase()));
  const chosen = candidates.find(user => user.id === selected);
  const choose = (user: Candidate) => { onSelect(user.id); setQuery(''); setOpen(false); };

  return <div className="space-y-2">
    <label htmlFor={id} className="block text-xs font-medium">{label}</label>
    <div className="relative">
      <input ref={input} id={id} role="combobox" aria-autocomplete="list" aria-expanded={open}
        aria-busy={loading}
        aria-controls={`${id}-list`} aria-activedescendant={open && matches[active] ? `${id}-option-${active}` : undefined}
        disabled={disabled} value={open ? query : chosen?.label ?? selectedLabel ?? ''} placeholder="Search by name or email..."
        className="w-full rounded-lg border border-border bg-background py-2 pl-3 pr-9 text-sm focus:outline-none focus:ring-2 focus:ring-hcl-blue"
        onFocus={() => { setOpen(true); setQuery(''); onSearch?.(''); setActive(0); }}
        onChange={event => { setQuery(event.target.value); onSearch?.(event.target.value); setOpen(true); setActive(0); }}
        onBlur={() => setOpen(false)}
        onKeyDown={event => {
          if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
            event.preventDefault(); setOpen(true);
            if (event.key === 'ArrowDown' && active === matches.length - 1 && onLoadMore && !loading) onLoadMore();
            setActive(index => Math.max(0, Math.min(matches.length - 1, index + (event.key === 'ArrowDown' ? 1 : -1))));
          } else if (event.key === 'Enter' && open) {
            event.preventDefault();
            if (error) onRetry?.();
            else if (matches[active]) choose(matches[active]);
          } else if (event.key === 'Escape' && open) { event.preventDefault(); event.stopPropagation(); setOpen(false); }
        }} />
      <ChevronDown aria-hidden="true" className="pointer-events-none absolute right-3 top-2.5 h-4 w-4" />
      {open && createPortal(<div style={position}
        className="z-[100] overflow-y-auto rounded-lg border border-border bg-surface p-1 shadow-xl">
        <div id={`${id}-list`} role="listbox" aria-label="Eligible assignees" aria-busy={loading}>
        {matches.map((user, index) => <div key={user.id} id={`${id}-option-${index}`} role="option" aria-selected={user.id === selected}
          className={`cursor-pointer rounded p-2 ${index === active ? 'bg-surface-muted' : ''}`}
          onMouseDown={event => event.preventDefault()} onMouseMove={() => setActive(index)} onClick={() => choose(user)}>
          {user.roles.length ? <AssigneeIdentity user={user} /> : <span className="text-sm">{user.label}</span>}
        </div>)}
        </div>
        {loading ? <p role="status" className="p-3 text-sm">Loading assignees...</p> : null}
        {error ? <div role="alert" className="p-3 text-sm">Unable to load assignees. <button type="button" onMouseDown={event => event.preventDefault()} onClick={onRetry} className="underline">Retry</button></div> : null}
        {onLoadMore ? <button type="button" className="w-full rounded p-2 text-sm text-hcl-blue focus-visible:ring-2" disabled={loading} onMouseDown={event => event.preventDefault()} onClick={onLoadMore}>Load more assignees</button> : null}
        {!matches.length && !loading && !error && <div className="p-3 text-sm" role="status">
          <p>{query.trim() ? 'No eligible assignees found' : 'No eligible assignees'}</p>
          <p className="mt-1 text-xs text-hcl-muted">{query.trim() ? 'Try searching by name or email.' : 'Add an active Security Analyst or Developer to this tenant before assigning this investigation.'}</p>
        </div>}
      </div>, document.body)}
    </div>
    {chosen && !open && !compact ? <AssigneeIdentity user={chosen} /> : null}
  </div>;
}
