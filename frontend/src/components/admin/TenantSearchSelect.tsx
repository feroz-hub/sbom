'use client';

import { useEffect, useState } from 'react';
import { listPlatformTenants, type TenantSummary } from '@/lib/api';

export function TenantSearchSelect({ value, onChange }: {
  value: TenantSummary | null;
  onChange: (tenant: TenantSummary | null) => void;
}) {
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(1);
  const [tenants, setTenants] = useState<TenantSummary[]>([]);
  const [error, setError] = useState('');
  useEffect(() => {
    let cancelled = false;
    const timer = setTimeout(() => {
      listPlatformTenants(query, page).then(result => {
        if (!cancelled) { setTenants(result); setError(''); }
      }).catch(() => { if (!cancelled) setError('Unable to load tenants. Try searching again.'); });
    }, 250);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [query, page]);
  return <fieldset className="min-w-0 space-y-2 rounded-lg border border-border bg-surface p-3 text-sm"><legend>Tenant</legend>
    <label className="block">Search tenants by name or slug
      <input className="block w-full rounded border p-2 bg-background" value={query} onChange={event => {
        setQuery(event.target.value); setPage(1); onChange(null);
      }} />
    </label>
    {value ? <p>{value.name} — {value.slug} <button type="button" onClick={() => onChange(null)}>Change tenant</button></p>
      : <ul className="max-h-40 space-y-1 overflow-y-auto rounded-lg border border-border p-1">{tenants.map(tenant => <li key={tenant.id}><button className="w-full rounded-md px-3 py-2 text-left hover:bg-surface-muted focus-visible:ring-2 focus-visible:ring-primary" type="button" disabled={tenant.status !== 'ACTIVE'}
        onClick={() => onChange(tenant)}>{tenant.name} — {tenant.slug}{tenant.status !== 'ACTIVE' ? ` (${tenant.status})` : ''}</button></li>)}</ul>}
    <button type="button" disabled={page === 1} onClick={() => setPage(page - 1)}>Previous tenants</button>
    <button type="button" disabled={tenants.length < 50} onClick={() => setPage(page + 1)}>Next tenants</button>
    {error && <p role="alert">{error}</p>}
  </fieldset>;
}
