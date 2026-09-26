'use client';
import { FormEvent, useEffect, useState } from 'react';
import { useAuth } from '@/hooks/useAuth';
import { ConfirmationDialog } from '@/components/ui/ConfirmationDialog';

type Membership = { membership_id: number; tenant_id: number; tenant_name: string; membership_status: string; roles: string[]; primary_role: string; role_assignment_version: number };
type Audit = { id: number; action: string; outcome: string; timestamp: string };
type User = Partial<Membership> & { id?: number; user_id?: number; display_name: string; first_name: string | null; last_name: string | null; email: string; phone: string | null; account_status: string; providers: string[]; email_verified: boolean; last_login_at: string | null; created_at: string; updated_at: string; tenant_memberships?: Membership[]; security?: { failed_login_count: number; locked_until: string | null } | null; activity?: { items: Audit[]; total: number } };
const statuses = ['ACTIVE', 'PENDING_EMAIL_VERIFICATION', 'LOCKED', 'DISABLED', 'FORCE_PASSWORD_CHANGE'];
const baseRoles = ['SECURITY_ANALYST', 'DEVELOPER', 'VIEWER'];
const inputClass = 'rounded border p-2 bg-background';

async function api(path: string, tenant: string | number | null, method = 'GET', body?: unknown) {
  const response = await fetch(`/api/backend/api${path}`, { method, headers: { 'Content-Type': 'application/json', ...(tenant ? { 'X-Tenant-ID': String(tenant) } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
  const data = await response.json();
  if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : data.detail?.message || 'Request failed. Refresh the user and check your permissions.');
  return data;
}

export default function UserLifecycle() {
  const { user, activeTenantId, hasPermission } = useAuth();
  const platform = Boolean(user?.isPlatformAdmin && hasPermission('platform:user:read'));
  const scope = activeTenantId || (user?.tenantId ? String(user.tenantId) : null);
  const allowed = platform || Boolean(scope && hasPermission('tenant:user:read'));
  // Remount on scope changes so no prior tenant's data can remain visible.
  return allowed ? <Lifecycle key={`${platform}:${scope}`} platform={platform} scope={scope} permission={hasPermission} /> : <p>Administrator permission and a selected tenant are required.</p>;
}

function Lifecycle({ platform, scope, permission }: { platform: boolean; scope: string | null; permission: (code: string) => boolean }) {
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('');
  const [role, setRole] = useState('');
  const [provider, setProvider] = useState('');
  const [tenantFilter, setTenantFilter] = useState('');
  const [sort, setSort] = useState('name');
  const [page, setPage] = useState(1);
  const [rows, setRows] = useState<User[]>([]);
  const [total, setTotal] = useState(0);
  const [selected, setSelected] = useState<User | null>(null);
  const [detail, setDetail] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [revision, setRevision] = useState(0);
  const [confirmation, setConfirmation] = useState<{ text: string; run: () => Promise<void> } | null>(null);
  const canGlobal = platform && permission('platform:user:manage_status');
  const canProfile = permission(platform ? 'platform:user:write' : 'tenant:user:update');
  const canMember = permission('tenant:user:update');
  const canInvite = permission('tenant:user:invite');
  const roles = [...(platform ? ['TENANT_ADMIN'] : []), ...baseRoles];
  const prefix = platform ? '/platform/users' : `/tenants/${scope}/users`;
  const identifier = (u: User) => platform ? u.id : u.membership_id;
  useEffect(() => {
    let current = true;
    const query = new URLSearchParams({ page: String(page), page_size: '20', search });
    if (status) query.set(platform ? 'local_status' : 'account_status', status);
    if (role) query.set('role', role);
    if (platform) { query.set('sort_by', sort); if (provider) query.set('provider', provider); if (tenantFilter) query.set('tenant_id', tenantFilter); }
    api(`${prefix}?${query}`, scope).then(data => { if (current) { setRows(data.items); setTotal(data.total); } }).catch(e => { if (current) setError(e.message); }).finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [prefix, scope, platform, page, search, status, role, provider, tenantFilter, sort, revision]);
  useEffect(() => {
    if (!selected) return;
    let current = true;
    api(`${prefix}/${platform ? selected.id : selected.membership_id}`, scope).then(data => { if (current) setDetail(data); }).catch(e => { if (current) setError(e.message); });
    return () => { current = false; };
  }, [selected, prefix, platform, scope, revision]);
  function filter(set: (value: string) => void, value: string) { set(value); setPage(1); setLoading(true); setError(''); }
  async function mutate(path: string, method: string, body?: unknown, tenant: string | number | null = scope) {
    setBusy(true); setError(''); setNotice('');
    try { const data = await api(path, tenant, method, body); setNotice(data.delivery ? `Activation delivery: ${data.delivery.status}.` : 'Changes saved.'); setDetail(null); setRevision(n => n + 1); }
    catch (e) { setError(e instanceof Error ? e.message : 'Request failed.'); }
    finally { setBusy(false); }
  }
  function confirm(text: string, run: () => Promise<void>) { setConfirmation({ text, run }); }
  const uid = detail?.id ?? detail?.user_id;
  const memberships = detail ? (platform ? detail.tenant_memberships || [] : [detail as Membership]) : [];
  return <section className="space-y-5">
    <h1 className="text-2xl font-semibold">User management</h1>
    <p>{platform ? 'Platform users and all tenant memberships' : 'Users in the selected tenant'}</p>
    <div className="flex flex-wrap gap-3">
      <label>Search <input className={inputClass} value={search} onChange={e => filter(setSearch, e.target.value)} /></label>
      <label>Account status <select className={inputClass} value={status} onChange={e => filter(setStatus, e.target.value)}><option value="">All</option>{statuses.map(s => <option key={s}>{s}</option>)}</select></label>
      <label>Role <select className={inputClass} value={role} onChange={e => filter(setRole, e.target.value)}><option value="">All</option>{roles.map(r => <option key={r}>{r}</option>)}</select></label>
      {platform && <><label>Provider <select className={inputClass} value={provider} onChange={e => filter(setProvider, e.target.value)}><option value="">All</option><option>NATIVE</option><option>HCL_CS</option></select></label>
        <label>Tenant ID <input className={inputClass} type="number" min="1" value={tenantFilter} onChange={e => filter(setTenantFilter, e.target.value)} /></label>
        <label>Sort <select className={inputClass} value={sort} onChange={e => filter(setSort, e.target.value)}>{['name', 'email', 'created_at', 'last_login_at'].map(s => <option key={s}>{s}</option>)}</select></label></>}
    </div>
    {error && <div><p role="alert">{error}</p><button onClick={() => { setError(''); setLoading(true); setRevision(n => n + 1); }}>Retry loading</button></div>}{notice && <p role="status">{notice}</p>}
    {loading ? <p role="status">Loading users…</p> : <><ul className="space-y-2">{rows.map(u => <li key={identifier(u)}><button className="underline" onClick={() => { setDetail(null); setSelected(u); setError(''); }}>{u.display_name || u.email}</button> — {u.email} · {u.account_status}{u.membership_status && ` · Membership ${u.membership_status}`}{u.roles && ` · ${u.roles.join(', ')}`}</li>)}</ul>{!rows.length && <p>No users found.</p>}</>}
    <div className="flex gap-3"><button disabled={page === 1 || loading} onClick={() => { setLoading(true); setPage(p => p - 1); }}>Previous</button><span>Page {page} · {total} users</span><button disabled={page * 20 >= total || loading} onClick={() => { setLoading(true); setPage(p => p + 1); }}>Next</button></div>
    {selected && !detail && !error && <p role="status">Loading user details…</p>}
    {detail && <article className="border rounded p-5 space-y-4" key={`${uid}:${revision}`}>
      <h2 className="text-xl font-semibold">{detail.display_name || detail.email}</h2><p>{detail.email} · Account: {detail.account_status} · {(detail.providers || []).map(p => p === 'HCL_CS' ? 'HCL.CS' : 'Native').join(' + ')}</p>
      <p>Email verified: {detail.email_verified ? 'Yes' : 'No'} · Last login: {detail.last_login_at || 'Never'}</p><p>Created: {detail.created_at} · Updated: {detail.updated_at}</p>
      {platform && detail.security && <p>Failed logins: {detail.security.failed_login_count} · Locked until: {detail.security.locked_until || 'Not locked'}</p>}
      {canProfile && <form className="flex flex-wrap gap-3" onSubmit={(e: FormEvent<HTMLFormElement>) => { e.preventDefault(); const data = new FormData(e.currentTarget); void mutate(`${prefix}/${identifier(detail)}/profile`, 'PATCH', Object.fromEntries(['first_name', 'last_name', 'phone'].map(k => [k, data.get(k)]))); }}>
        {['first_name', 'last_name', 'phone'].map(k => <label key={k}>{k.replace('_', ' ')} <input className={inputClass} name={k} defaultValue={detail[k as 'first_name'] || ''} maxLength={k === 'phone' ? 64 : 120} required={k !== 'phone'} /></label>)}<button disabled={busy}>Save profile</button><p>Profile changes apply to this user across tenants. Email cannot be edited here.</p>
      </form>}
      {canGlobal && <div className="flex gap-4 flex-wrap">
        {detail.account_status !== 'DISABLED' ? <button disabled={busy} onClick={() => confirm('Disable account globally? Access to every tenant will be blocked.', () => mutate(`/platform/users/${uid}/status`, 'PATCH', { status: 'DISABLED' }))}>Disable account globally</button> : <button disabled={busy} onClick={() => void mutate(`/platform/users/${uid}/status`, 'PATCH', { status: 'ACTIVE' })}>Enable account globally</button>}
        {detail.account_status === 'LOCKED' && <button disabled={busy} onClick={() => void mutate(`/platform/users/${uid}/unlock`, 'POST')}>Unlock account</button>}
        {detail.account_status === 'ACTIVE' && detail.providers.includes('NATIVE') && <button disabled={busy} onClick={() => confirm('Force password change? All current native tokens will be revoked. The user must set a new password at their next native sign-in.', () => mutate(`/platform/users/${uid}/force-password-change`, 'POST'))}>Force password change</button>}
      </div>}
      <h3 className="font-semibold">Tenant memberships</h3>
      {memberships.map(m => <section key={m.membership_id} className="border rounded p-3 space-y-3"><h4>{m.tenant_name} · {m.membership_status}</h4><p>Roles: {m.roles.join(', ')} · Primary: {m.primary_role}</p>
        {canMember && <><button disabled={busy} onClick={() => { const path = `/tenants/${m.tenant_id}/users/${m.membership_id}/${m.membership_status === 'ACTIVE' ? 'deactivate' : 'activate'}`; const run = () => mutate(path, 'POST', undefined, m.tenant_id); if (m.membership_status === 'ACTIVE') confirm(`Deactivate access to ${m.tenant_name}? Other tenants remain unaffected.`, run); else void run(); }}>{m.membership_status === 'ACTIVE' ? `Deactivate access to ${m.tenant_name}` : `Reactivate access to ${m.tenant_name}`}</button>
          <form onSubmit={e => { e.preventDefault(); const data = new FormData(e.currentTarget); const codes = data.getAll('roles').map(String); const primary = String(data.get('primary')); const run = () => mutate(`/tenants/${m.tenant_id}/users/${uid}/roles`, 'PUT', { role_codes: codes, primary_role_code: primary, expected_version: m.role_assignment_version }, m.tenant_id); if (m.roles.some(r => !codes.includes(r))) confirm(`Remove roles in ${m.tenant_name}? Permissions will be removed immediately.`, run); else void run(); }}>
            <fieldset disabled={busy || (!platform && m.roles.includes('TENANT_ADMIN'))}><legend>Change tenant roles</legend>{roles.map(r => <label className="mr-3" key={r}><input type="checkbox" name="roles" value={r} defaultChecked={m.roles.includes(r)} /> {r}</label>)}<label>Primary role <select name="primary" className={inputClass} defaultValue={m.primary_role}>{roles.map(r => <option key={r}>{r}</option>)}</select></label><button>Save roles</button></fieldset>
          </form></>}
        {canInvite && detail.account_status === 'PENDING_EMAIL_VERIFICATION' && detail.providers.includes('NATIVE') && <button disabled={busy} onClick={() => void mutate(`/tenants/${m.tenant_id}/native-users/${uid}/resend-activation`, 'POST', undefined, m.tenant_id)}>Resend activation</button>}
      </section>)}
      {platform && canInvite && <form onSubmit={e => { e.preventDefault(); const data = new FormData(e.currentTarget); const tenant = Number(data.get('tenant')); void mutate(`/tenants/${tenant}/memberships`, 'POST', { user_id: uid, role_codes: data.getAll('roles') }, tenant); }}><h3>Add existing user to another tenant</h3><label>New tenant ID <input className={inputClass} name="tenant" type="number" min="1" required /></label>{roles.map(r => <label className="mr-3" key={r}><input type="checkbox" name="roles" value={r} defaultChecked={r === 'VIEWER'} /> {r}</label>)}<button disabled={busy}>Add membership</button></form>}
      <h3 className="font-semibold">Recent audit activity</h3><ul>{detail.activity?.items.map(a => <li key={a.id}>{a.timestamp} · {a.action} · {a.outcome}</li>)}</ul><p>{detail.activity?.total || 0} recorded events; showing the most recent 50.</p>
    </article>}
    <ConfirmationDialog open={Boolean(confirmation)} title="Confirm access change" description={confirmation?.text || ''} confirmLabel="Confirm" onClose={() => setConfirmation(null)} onConfirm={() => { const run = confirmation?.run; setConfirmation(null); if (run) void run(); }} />
  </section>;
}
