'use client';
import { FormEvent, useEffect, useState } from 'react';
import { useAuth } from '@/hooks/useAuth';
import { UserStatusBadge } from './StatusBadges';
import { ConfirmationDialog } from '@/components/ui/ConfirmationDialog';

type Membership = { membership_id: number; tenant_id: number; tenant_name: string; membership_status: string; roles: string[]; primary_role: string; role_assignment_version: number };
type Audit = { actor_user_id?: number | null; tenant_id?: number | null; id: number; action: string; outcome: string; timestamp: string };
type User = Partial<Membership> & { active_tenant_count?: number; id?: number; user_id?: number; display_name: string; first_name: string | null; last_name: string | null; email: string; phone: string | null; account_status: string; providers: string[]; email_verified: boolean; last_login_at: string | null; created_at: string; updated_at: string; tenant_memberships?: Membership[]; security?: { password_changed_at?: string | null; failed_login_count: number; locked_until: string | null } | null; activity?: { items: Audit[]; total: number } };
const statuses = ['ACTIVE', 'PENDING_EMAIL_VERIFICATION', 'LOCKED', 'DISABLED', 'FORCE_PASSWORD_CHANGE'];
const baseRoles = ['SECURITY_ANALYST', 'DEVELOPER', 'VIEWER'];
const inputClass = 'rounded-md border border-border-subtle px-3 py-2 bg-background focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary';
const readable = (value: string) => value.toLowerCase().replaceAll('_', ' ');
const date = (value?: string | null) => value ? new Date(value).toLocaleString() : 'Never';

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
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3" aria-label="Directory summary"><div className="rounded-lg border p-4"><p className="text-sm">Matching users</p><strong className="text-2xl">{total}</strong></div><div className="rounded-lg border p-4"><p className="text-sm">Scope</p><strong>{platform ? 'All authorized tenants' : 'Selected tenant only'}</strong></div><div className="rounded-lg border p-4"><p className="text-sm">Account filter</p><strong>{status ? readable(status) : 'All statuses'}</strong></div></div>
    {loading ? <div className="animate-pulse rounded-lg border p-6" role="status">Loading users…</div> : <div className="overflow-x-auto rounded-lg border border-border-subtle"><table className="w-full text-left text-sm"><caption className="sr-only">Users and global account status. Membership access is shown separately.</caption><thead className="bg-surface-muted"><tr>{['Name / Email', 'Provider', 'Account status', 'Tenant memberships / Roles', 'Last login', 'Created', 'Actions'].map(c => <th scope="col" className="p-3 font-semibold" key={c}>{c}</th>)}</tr></thead><tbody>{rows.map(u => <tr className="border-t hover:bg-surface-muted" key={identifier(u)}><td className="p-3"><button className="font-semibold underline focus-visible:outline" onClick={() => { setDetail(null); setSelected(u); setError(''); }}>{u.display_name || u.email}</button><p className="text-hcl-muted">{u.email}</p></td><td className="p-3">{(u.providers || []).map(p => p === 'HCL_CS' ? 'HCL.CS' : p).join(' + ')}</td><td className="p-3"><UserStatusBadge status={u.account_status} /></td><td className="p-3">{platform ? <span>{u.active_tenant_count ?? u.tenant_memberships?.length ?? '—'} active memberships · Open details for roles by tenant</span> : <><p>Membership: {u.membership_status}</p><p>{u.roles?.join(', ')}</p></>}</td><td className="p-3">{date(u.last_login_at)}</td><td className="p-3">{date(u.created_at)}</td><td className="p-3"><button aria-label={`View details for ${u.display_name || u.email}`} onClick={() => { setDetail(null); setSelected(u); }}>View</button></td></tr>)}</tbody></table>{!rows.length && <p className="p-8 text-center">No users found.</p>}</div>}
    <div className="flex gap-3"><button disabled={page === 1 || loading} onClick={() => { setLoading(true); setPage(p => p - 1); }}>Previous</button><span>Page {page} · {total} users</span><button disabled={page * 20 >= total || loading} onClick={() => { setLoading(true); setPage(p => p + 1); }}>Next</button></div>
    {selected && !detail && !error && <p role="status">Loading user details…</p>}
    {detail && <article className="border rounded p-5 space-y-4" key={`${uid}:${revision}`}>
      <h2 tabIndex={-1} ref={node => { if (node && selected) node.focus(); }} className="text-xl font-semibold outline-none">{detail.display_name || detail.email}</h2><p>{detail.email} · Account: {detail.account_status} · {(detail.providers || []).map(p => p === 'HCL_CS' ? 'HCL.CS' : 'Native').join(' + ')}</p>
      <h3 className="font-semibold">Account security & authentication activity</h3><p>Email verified: {detail.email_verified ? 'Yes' : 'No'} · Last login: {detail.last_login_at || 'Never'}</p><p>Created: {detail.created_at} · Updated: {detail.updated_at}</p>
      {platform && detail.security && <p>Password last changed: {date(detail.security.password_changed_at)} · Failed logins: {detail.security.failed_login_count} · Locked until: {detail.security.locked_until || 'Not locked'}</p>}
      <h3 className="font-semibold">Profile</h3><p>{detail.first_name} {detail.last_name} · {detail.phone || 'No phone recorded'}</p><h3 className="font-semibold">Identity providers</h3><p>{detail.providers.join(' + ')}</p>
      {canProfile && <form className="flex flex-wrap gap-3" onSubmit={(e: FormEvent<HTMLFormElement>) => { e.preventDefault(); const data = new FormData(e.currentTarget); void mutate(`${prefix}/${identifier(detail)}/profile`, 'PATCH', Object.fromEntries(['first_name', 'last_name', 'phone'].map(k => [k, data.get(k)]))); }}>
        {['first_name', 'last_name', 'phone'].map(k => <label key={k}>{k.replace('_', ' ')} <input className={inputClass} name={k} defaultValue={detail[k as 'first_name'] || ''} maxLength={k === 'phone' ? 64 : 120} required={k !== 'phone'} /></label>)}<button disabled={busy}>Save profile</button><p>Profile changes apply to this user across tenants. Email cannot be edited here.</p>
      </form>}
      {canGlobal && <div className="flex gap-4 flex-wrap">
        {detail.account_status !== 'DISABLED' ? <button disabled={busy} onClick={() => confirm(`Disable ${detail.display_name} globally? Access to every tenant will be blocked.`, () => mutate(`/platform/users/${uid}/status`, 'PATCH', { status: 'DISABLED' }))}>Disable account globally</button> : <button disabled={busy} onClick={() => confirm(`Enable ${detail.display_name} globally? Active tenant memberships may regain access.`, () => mutate(`/platform/users/${uid}/status`, 'PATCH', { status: 'ACTIVE' }))}>Enable account globally</button>}
        {detail.account_status === 'LOCKED' && <button disabled={busy} onClick={() => confirm(`Unlock ${detail.display_name}'s account? Clear the authentication lock across all tenants.`, () => mutate(`/platform/users/${uid}/unlock`, 'POST'))}>Unlock account</button>}
        {detail.account_status === 'ACTIVE' && detail.providers.includes('NATIVE') && <button disabled={busy} onClick={() => confirm(`Force password change for ${detail.display_name}? All current native sessions will be revoked. The user must set a new password at their next native sign-in.`, () => mutate(`/platform/users/${uid}/force-password-change`, 'POST'))}>Force password change</button>}
        {detail.providers.includes('NATIVE') && <button disabled={busy} onClick={() => confirm(`Log out all native sessions for ${detail.display_name}? The user must sign in again in every tenant.`, () => mutate(`/platform/users/${uid}/logout-all`, 'POST'))}>Logout all native sessions</button>}
      </div>}
      <h3 className="font-semibold">Tenant memberships</h3>
      {memberships.map(m => <section key={m.membership_id} className="border rounded p-3 space-y-3"><h4>{m.tenant_name} · {m.membership_status}</h4><p>Roles: {m.roles.join(', ')} · Primary: {m.primary_role}</p>
        {canMember && <><button disabled={busy} onClick={() => { const path = `/tenants/${m.tenant_id}/users/${m.membership_id}/${m.membership_status === 'ACTIVE' ? 'deactivate' : 'activate'}`; const run = () => mutate(path, 'POST', undefined, m.tenant_id); if (m.membership_status === 'ACTIVE') confirm(`Deactivate ${detail.display_name} in ${m.tenant_name}? Other tenants remain unaffected.`, run); else confirm(`Reactivate ${detail.display_name} in ${m.tenant_name}? This restores this membership only.`, run); }}>{m.membership_status === 'ACTIVE' ? `Deactivate access to ${m.tenant_name}` : `Reactivate access to ${m.tenant_name}`}</button>
          <form onSubmit={e => { e.preventDefault(); const data = new FormData(e.currentTarget); const codes = data.getAll('roles').map(String); const primary = String(data.get('primary')); const run = () => mutate(`/tenants/${m.tenant_id}/users/${uid}/roles`, 'PUT', { role_codes: codes, primary_role_code: primary, expected_version: m.role_assignment_version }, m.tenant_id); if (m.roles.some(r => !codes.includes(r))) confirm(`Remove roles for ${detail.display_name} in ${m.tenant_name}? Permissions will be removed immediately.`, run); else confirm(`Replace roles for ${detail.display_name} in ${m.tenant_name}? This changes this membership only.`, run); }}>
            <fieldset disabled={busy || (!platform && m.roles.includes('TENANT_ADMIN'))}><legend>Change tenant roles</legend>{roles.map(r => <label className="mr-3" key={r}><input type="checkbox" name="roles" value={r} defaultChecked={m.roles.includes(r)} /> {r}</label>)}<label>Primary role <select name="primary" className={inputClass} defaultValue={m.primary_role}>{roles.map(r => <option key={r}>{r}</option>)}</select></label><button>Save roles</button></fieldset>
          </form></>}
        {canInvite && detail.account_status === 'PENDING_EMAIL_VERIFICATION' && detail.providers.includes('NATIVE') && <button disabled={busy} onClick={() => confirm(`Resend activation to ${detail.display_name} for ${m.tenant_name}? The previous activation link will stop working.`, () => mutate(`/tenants/${m.tenant_id}/native-users/${uid}/resend-activation`, 'POST', undefined, m.tenant_id))}>Resend activation</button>}
      </section>)}
      {platform && canInvite && <form onSubmit={e => { e.preventDefault(); const data = new FormData(e.currentTarget); const tenant = Number(data.get('tenant')); void mutate(`/tenants/${tenant}/memberships`, 'POST', { user_id: uid, role_codes: data.getAll('roles') }, tenant); }}><h3>Add existing user to another tenant</h3><label>New tenant ID <input className={inputClass} name="tenant" type="number" min="1" required /></label>{roles.map(r => <label className="mr-3" key={r}><input type="checkbox" name="roles" value={r} defaultChecked={r === 'VIEWER'} /> {r}</label>)}<button disabled={busy}>Add membership</button></form>}
      <h3 id="audit" className="font-semibold">Recent audit activity</h3><ol aria-label="Audit timeline" className="border-l-2 pl-4 space-y-3">{detail.activity?.items.map(a => <li key={a.id}><time>{a.timestamp}</time><p className="capitalize font-medium">{readable(a.action)} · {a.outcome}</p><p className="text-sm">Actor: {a.actor_user_id ?? 'System'}{a.tenant_id ? ` · Tenant ${a.tenant_id}` : ' · Account'}</p></li>)}</ol><p>{detail.activity?.total || 0} recorded events; showing the most recent 50.</p>
    </article>}
    <ConfirmationDialog open={Boolean(confirmation)} title="Confirm access change" description={confirmation?.text || ''} confirmLabel="Confirm" onClose={() => setConfirmation(null)} onConfirm={() => { const run = confirmation?.run; setConfirmation(null); if (run) void run(); }} />
  </section>;
}
