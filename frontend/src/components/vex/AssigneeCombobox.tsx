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
export function AssigneeCombobox({ candidates, selected, onSelect, disabled = false }: {
  candidates: Candidate[];
  selected: string;
  onSelect: (id: string) => void;
  disabled?: boolean;
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
      const below = window.innerHeight - rect.bottom - 12;
      const above = below < 160 && rect.top > below;
      setPosition({ position: 'fixed', left: Math.max(8, rect.left), width: Math.min(rect.width, window.innerWidth - 16),
        top: above ? undefined : rect.bottom + 4, bottom: above ? window.innerHeight - rect.top + 4 : undefined,
        maxHeight: Math.max(64, Math.min(256, above ? rect.top - 12 : below)) });
    };
    place();
    window.addEventListener('scroll', place, true);
    window.addEventListener('resize', place);
    return () => { window.removeEventListener('scroll', place, true); window.removeEventListener('resize', place); };
  }, [open]);
  const matches = candidates.filter(user => `${user.label} ${user.email ?? ''}`.toLowerCase().includes(query.trim().toLowerCase()));
  const chosen = candidates.find(user => user.id === selected);
  const choose = (user: Candidate) => { onSelect(user.id); setQuery(''); setOpen(false); };

  return <div className="space-y-2">
    <label htmlFor={id} className="block text-sm font-medium">Assignee</label>
    <div className="relative">
      <input ref={input} id={id} role="combobox" aria-autocomplete="list" aria-expanded={open}
        aria-controls={`${id}-list`} aria-activedescendant={open && matches[active] ? `${id}-option-${active}` : undefined}
        disabled={disabled} value={open ? query : chosen?.label ?? ''} placeholder="Search by name or email..."
        className="w-full rounded-lg border border-border bg-background py-2 pl-3 pr-9 text-sm focus:outline-none focus:ring-2 focus:ring-hcl-blue"
        onFocus={() => { setOpen(true); setQuery(''); setActive(0); }}
        onChange={event => { setQuery(event.target.value); setOpen(true); setActive(0); }}
        onBlur={() => setOpen(false)}
        onKeyDown={event => {
          if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
            event.preventDefault(); setOpen(true);
            setActive(index => Math.max(0, Math.min(matches.length - 1, index + (event.key === 'ArrowDown' ? 1 : -1))));
          } else if (event.key === 'Enter' && open) {
            event.preventDefault(); if (matches[active]) choose(matches[active]);
          } else if (event.key === 'Escape' && open) { event.preventDefault(); event.stopPropagation(); setOpen(false); }
        }} />
      <ChevronDown aria-hidden="true" className="pointer-events-none absolute right-3 top-2.5 h-4 w-4" />
      {open && createPortal(<div id={`${id}-list`} role="listbox" aria-label="Eligible assignees" style={position}
        className="z-[100] overflow-y-auto rounded-lg border border-border bg-surface p-1 shadow-xl">
        {matches.map((user, index) => <div key={user.id} id={`${id}-option-${index}`} role="option" aria-selected={user.id === selected}
          className={`cursor-pointer rounded p-2 ${index === active ? 'bg-surface-muted' : ''}`}
          onMouseDown={event => event.preventDefault()} onMouseMove={() => setActive(index)} onClick={() => choose(user)}>
          <AssigneeIdentity user={user} />
        </div>)}
        {!matches.length && <div className="p-3 text-sm" role="status">
          <p>{query.trim() ? 'No eligible assignees found' : 'No eligible assignees'}</p>
          <p className="mt-1 text-xs text-hcl-muted">{query.trim() ? 'Try searching by name or email.' : 'Add an active Security Analyst or Developer to this tenant before assigning this investigation.'}</p>
        </div>}
      </div>, document.body)}
    </div>
    {chosen && !open ? <AssigneeIdentity user={chosen} /> : null}
  </div>;
}
