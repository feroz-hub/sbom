'use client';

import { useEffect, useRef, useState } from 'react';
import { listPlatformTenants, type TenantSummary } from '@/lib/api';

export function TenantSearchSelect({ value, onChange, allowAll = false }: {
  value: TenantSummary | null;
  onChange: (tenant: TenantSummary | null) => void;
  allowAll?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(1);
  const [tenants, setTenants] = useState<TenantSummary[]>([]);
  const [error, setError] = useState('');
  const [revision, setRevision] = useState(0);
  const containerRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    let cancelled = false;
    const timer = setTimeout(() => {
      listPlatformTenants(query, page).then(result => {
        if (!cancelled) { setTenants(result); setError(''); }
      }).catch(() => { if (!cancelled) setError('Some filter information could not be loaded.'); });
    }, 250);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [query, page, revision]);

  // Close popover on outside click
  useEffect(() => {
    if (!open) return;
    const close = (event: PointerEvent) => {
      if (!containerRef.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener('pointerdown', close);
    return () => document.removeEventListener('pointerdown', close);
  }, [open]);

  return <div ref={containerRef} className="relative min-w-0">
    <label className="block text-[.8125rem] font-medium">Tenant
      <button
        ref={triggerRef}
        type="button"
        aria-expanded={open}
        aria-haspopup="listbox"
        onClick={() => setOpen(v => !v)}
        className="mt-1.5 flex w-full min-h-[44px] items-center justify-between rounded-[.625rem] border border-border bg-surface px-3.5 py-2 text-sm text-foreground focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary"
      >
        <span className="truncate">{value ? value.name : allowAll ? 'All tenants' : 'Select tenant'}</span>
        <svg className="ml-2 h-4 w-4 shrink-0 text-hcl-muted" viewBox="0 0 16 16" fill="none" stroke="currentColor" aria-hidden="true"><path d="m4 6 4 4 4-4" /></svg>
      </button>
    </label>

    {error && <div role="alert" className="text-xs"><p>{error}</p>{allowAll && <p>User data is still available independently.</p>}<button type="button" onClick={() => setRevision(n => n + 1)}>Retry filters</button></div>}
    {open && <div className="absolute left-0 top-full z-30 mt-1 w-72 rounded-lg border border-border bg-surface p-3 shadow-lg space-y-2 text-sm"
      onKeyDown={event => { if (event.key === 'Escape') { setOpen(false); triggerRef.current?.focus(); } }}
    >
      <label className="block">
        <span className="sr-only">Search tenants by name or slug</span>
        <input
          className="block w-full rounded-md border border-border-subtle bg-background px-3 py-2 text-sm placeholder:text-hcl-muted focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary"
          placeholder="Search tenants…"
          value={query}
          onChange={event => { setQuery(event.target.value); setPage(1); }}
          // eslint-disable-next-line jsx-a11y/no-autofocus
          autoFocus
        />
      </label>
      <ul className="max-h-48 space-y-0.5 overflow-y-auto" role="listbox">
        {allowAll && <li role="option" aria-selected={!value}><button type="button" onClick={() => { onChange(null); setOpen(false); }}>All tenants</button></li>}
        {tenants.map(tenant => <li key={tenant.id} role="option" aria-selected={value?.id === tenant.id}>
          <button
            className="w-full rounded-md px-3 py-2 text-left hover:bg-surface-muted focus-visible:ring-2 focus-visible:ring-primary"
            type="button"
            disabled={Boolean(error) || (!allowAll && tenant.status !== 'ACTIVE')}
            onClick={() => { onChange(tenant); setOpen(false); }}
          >{tenant.name} — {tenant.slug}{tenant.status !== 'ACTIVE' ? ` (${tenant.status})` : ''}</button>
        </li>)}
      </ul>
      <div className="flex items-center justify-between border-t border-border-subtle pt-2">
        <button type="button" className="rounded px-2 py-1 text-xs hover:bg-surface-muted disabled:opacity-50" disabled={page === 1} onClick={() => setPage(page - 1)}>Previous tenants</button>
        <button type="button" className="rounded px-2 py-1 text-xs hover:bg-surface-muted disabled:opacity-50" disabled={tenants.length < 50} onClick={() => setPage(page + 1)}>Next tenants</button>
      </div>
    </div>}
  </div>;
}
