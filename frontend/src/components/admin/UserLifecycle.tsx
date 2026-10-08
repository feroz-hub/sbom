'use client';
import styles from './NativeUsers.module.css';
import { useToast } from '@/hooks/useToast';
import { UserActionsMenu } from './UserActionsMenu';
import { AlertTriangle, Users } from 'lucide-react';
import { RoleBadges } from './StatusBadges';
import { FormEvent, useEffect, useState } from 'react';
import { usePermissions } from '@/hooks/usePermission';
import { useAuth } from '@/hooks/useAuth';
import { UserStatusBadge } from './StatusBadges';
import { ConfirmationDialog } from '@/components/ui/ConfirmationDialog';
import { type TenantSummary } from '@/lib/api';
import { TenantSearchSelect } from './TenantSearchSelect';

type Membership = { membership_id: number; tenant_id: number; tenant_name: string; membership_status: string; roles: string[]; primary_role: string; role_assignment_version: number };
type Audit = { actor_user_id?: number | null; tenant_id?: number | null; id: number; action: string; outcome: string; timestamp: string };
type User = Partial<Membership> & { is_platform_admin?: boolean; active_tenant_count?: number; id?: number; user_id?: number; display_name: string; first_name: string | null; last_name: string | null; email: string; phone: string | null; account_status: string; providers: string[]; email_verified: boolean; last_login_at: string | null; created_at: string; updated_at: string; tenant_memberships?: Membership[]; security?: { password_changed_at?: string | null; failed_login_count: number; locked_until: string | null } | null; activity?: { items: Audit[]; total: number } };
const providerLabel = (value: string) => ({ NATIVE: 'Native', HCL_CS: 'HCL.CS', MICROSOFT_ENTRA: 'Microsoft Entra' }[value] || value);
const statuses = ['PENDING', 'SUSPENDED', 'ACTIVE', 'PENDING_EMAIL_VERIFICATION', 'LOCKED', 'DISABLED', 'FORCE_PASSWORD_CHANGE'];
const baseRoles = ['SECURITY_ANALYST', 'DEVELOPER', 'VIEWER'];
const inputClass = 'rounded-md border border-border-subtle px-3 py-2 bg-background focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary';
const readable = (value: string) => value.toLowerCase().replaceAll('_', ' ');
const date = (value?: string | null) => value ? new Date(value).toLocaleString() : 'Never';

class DirectoryRequestError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

async function api(path: string, tenant: string | number | null, method = 'GET', body?: unknown) {
  const response = await fetch(`/api/backend/api${path}`, { method, headers: { 'Content-Type': 'application/json', ...(!path.startsWith('/platform/') && tenant ? { 'X-Tenant-ID': String(tenant) } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
  const data = await response.json();
  if (!response.ok) throw new DirectoryRequestError(response.status, response.status === 403 ? 'Access denied. Your permissions do not allow this action.' : response.status === 409 ? 'The account has changed or this action is unavailable. Refresh the user and review their access.' : 'Unable to complete the request. Please review the information and try again.');
  return data;
}

export default function UserLifecycle({ onAdd, refreshKey = 0 }: { onAdd?: () => void; refreshKey?: number }) {
  const { user, activeTenantId } = useAuth();
  const { can: hasPermission } = usePermissions();
  const platform = Boolean(user?.isPlatformAdmin && hasPermission('platform:user:read'));
  const scope = activeTenantId || (user?.tenantId ? String(user.tenantId) : null);
  const allowed = platform || Boolean(scope && hasPermission('tenant:user:read'));
  // Remount on scope changes so no prior tenant's data can remain visible.
  return allowed ? <Lifecycle key={`${platform}:${scope}`} platform={platform} scope={scope} permission={hasPermission} onAdd={onAdd} refreshKey={refreshKey} /> : <p>Administrator permission and a selected tenant are required.</p>;
}

function Lifecycle({ platform, scope, permission, onAdd, refreshKey }: { platform: boolean; scope: string | null; permission: (code: string) => boolean; onAdd?: () => void; refreshKey: number }) {
  const { showToast } = useToast();
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('');
  const [role, setRole] = useState('');
  const [provider, setProvider] = useState('');
  const [tenantFilter, setTenantFilter] = useState<TenantSummary | null>(null);
  const [newTenant, setNewTenant] = useState<TenantSummary | null>(null);
  const [sort, setSort] = useState('name');
  const [page, setPage] = useState(1);
  const [rows, setRows] = useState<User[]>([]);
  const [total, setTotal] = useState(0);
  const [selected, setSelected] = useState<User | null>(null);
  const [detail, setDetail] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [directoryError, setDirectoryError] = useState('');
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
    setLoading(true);
    setDirectoryError('');
    const query = new URLSearchParams({ page: String(page), page_size: '20' });
    if (search.trim()) query.set('search', search.trim());
    if (status) query.set(platform ? 'local_status' : 'account_status', status);
    if (platform && role === 'PLATFORM_ADMIN') query.set('is_platform_admin', 'true');
    else if (role) query.set('role', role);
    if (platform) { query.set('sort_by', sort); if (provider) query.set('provider', provider); if (tenantFilter) query.set('tenant_id', String(tenantFilter.id)); }
    api(`${prefix}?${query}`, platform ? null : scope).then(data => { if (current) { setRows(data.items); setTotal(data.total); } }).catch(e => {
      if (current) setDirectoryError(e instanceof DirectoryRequestError && e.status === 403
        ? "You don't have permission to view this user directory."
        : `The ${platform ? 'platform' : 'tenant'} user directory could not be retrieved.`);
    }).finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [prefix, scope, platform, page, search, status, role, provider, tenantFilter, sort, revision, refreshKey]);
  useEffect(() => {
    if (!selected) return;
    let current = true;
    api(`${prefix}/${platform ? selected.id : selected.membership_id}`, scope).then(data => { if (current) setDetail(data); }).catch(e => { if (current) setError(e.message); });
    return () => { current = false; };
  }, [selected, prefix, platform, scope, revision]);
  function filter(set: (value: string) => void, value: string) { set(value); setPage(1); setLoading(true); setError(''); }
  async function mutate(path: string, method: string, body?: unknown, tenant: string | number | null = scope) {
    if (busy) return;
    setBusy(true); setError('');
    try { const data = await api(path, tenant, method, body); showToast(data.delivery ? `Activation delivery: ${data.delivery.status}.` : 'User updated successfully.', 'success'); setDetail(null); setRevision(n => n + 1); }
    catch (e) { setError(e instanceof Error ? e.message : 'Request failed.'); }
    finally { setBusy(false); }
  }
  function confirm(text: string, run: () => Promise<void>) { setConfirmation({ text, run }); }
  const uid = detail?.id ?? detail?.user_id;
  const memberships = detail ? (platform ? detail.tenant_memberships || [] : [detail as Membership]) : [];
  return <section className={`${styles.console} space-y-3`}>
    <header className="flex flex-wrap items-start justify-between gap-4"><div><p className="mb-1 text-xs font-semibold uppercase tracking-widest text-hcl-muted">Identity & access</p><h1 className="text-3xl font-semibold tracking-tight">{platform ? 'User Accounts' : 'Users & Access'}</h1><p className="mt-1 text-sm text-hcl-muted">{platform ? 'Manage SBOM Analyzer accounts, authentication identities and tenant access.' : 'Manage users, roles and access for the selected tenant.'}</p></div>{onAdd && (platform ? canGlobal : canInvite) && <button className="!bg-hcl-blue !text-white" onClick={onAdd}>+ Add User</button>}</header>
    <div className="grid grid-cols-[repeat(auto-fill,minmax(160px,1fr))] items-end gap-3 rounded-xl border border-border bg-surface px-5 py-4 shadow-sm">
      <label>Search <input placeholder="Search name or email…" className={inputClass} value={search} onChange={e => filter(setSearch, e.target.value)} /></label>
      <label>Account status <select className={inputClass} value={status} onChange={e => filter(setStatus, e.target.value)}><option value="">All</option>{statuses.map(s => <option key={s}>{s}</option>)}</select></label>
      <label>Role <select className={inputClass} value={role} onChange={e => filter(setRole, e.target.value)}><option value="">All</option>{(platform ? ['PLATFORM_ADMIN', ...roles] : roles).map(r => <option key={r}>{r}</option>)}</select></label>
      {platform && <><label>Provider <select className={inputClass} value={provider} onChange={e => filter(setProvider, e.target.value)}><option value="">All</option><option value="NATIVE">Native</option><option value="HCL_CS">HCL.CS</option><option value="MICROSOFT_ENTRA">Microsoft Entra</option></select></label>
        <TenantSearchSelect allowAll value={tenantFilter} onChange={tenant => { setTenantFilter(tenant); setPage(1); }} />
        <label>Sort <select className={inputClass} value={sort} onChange={e => filter(setSort, e.target.value)}>{['name', 'email', 'created_at', 'last_login_at'].map(s => <option key={s}>{s}</option>)}</select></label></>}
      {(search || status || role || provider || tenantFilter) && <button onClick={() => { setSearch(''); setStatus(''); setRole(''); setProvider(''); setTenantFilter(null); setPage(1); }}>Clear filters</button>}
    </div>
    {error && <div className="flex items-center gap-3 rounded-lg border border-amber-300 bg-amber-50 px-4 py-3 text-sm dark:border-amber-700 dark:bg-amber-950/30" role="alert"><AlertTriangle className="h-4 w-4 shrink-0 text-amber-600" aria-hidden="true" /><p className="flex-1 text-amber-800 dark:text-amber-200">{error}</p><button className="shrink-0 rounded-md border border-amber-300 bg-white px-3 py-1 text-xs font-semibold text-amber-700 hover:bg-amber-50 dark:border-amber-600 dark:bg-amber-900/50 dark:text-amber-200" onClick={() => { setError(''); setLoading(true); setRevision(n => n + 1); }}>Retry</button></div>}
    {directoryError && <div role="alert"><h2>Unable to load users</h2><p>{directoryError}</p><button onClick={() => { setLoading(true); setRevision(n => n + 1); }}>Retry</button></div>}
    {!directoryError && <>
    <p className="text-xs text-hcl-muted">{platform ? 'Platform directory · All authorized tenants and identity providers' : 'Tenant directory · Selected tenant only'} · {total} matching users</p>
    {loading ? <div className="animate-pulse rounded-lg border p-6" role="status">Loading users…</div> : <div className="rounded-xl border border-border-subtle shadow-sm"><table className={styles.directory}><caption className="sr-only">Users and global account status. Membership access is shown separately.</caption><thead className="bg-surface-muted"><tr>{['Name / Email', 'Provider', 'Account status', 'Tenant memberships / Roles', 'Last login', 'Created', 'Actions'].map(c => <th scope="col" className="px-3 py-2 font-semibold" key={c}>{c}</th>)}</tr></thead><tbody>{rows.map(u => <tr className="border-t hover:bg-surface-muted" key={identifier(u)}><td className="px-3 py-2"><span aria-hidden="true" className="mb-1 mr-2 inline-flex h-8 w-8 items-center justify-center rounded-full bg-surface-muted text-xs font-semibold text-hcl-blue">{(u.display_name || u.email).split(/\s+/).map(part => part[0]).slice(0, 2).join('').toUpperCase()}</span><button className="font-semibold text-hcl-navy hover:underline focus-visible:outline" onClick={() => { setDetail(null); setSelected(u); setError(''); }}>{u.display_name || u.email}</button><p className="text-hcl-muted">{u.email}</p></td><td className="px-3 py-2">{(u.providers || []).map(providerLabel).join(' + ')}</td><td className="px-3 py-2"><UserStatusBadge status={u.account_status} /></td><td className="px-3 py-2">{platform ? <span>{u.active_tenant_count ?? u.tenant_memberships?.length ?? 0} active tenant memberships{u.is_platform_admin && <span className="block">Platform Administrator</span>} · Open details for roles by tenant</span> : <><p>Membership: {u.membership_status}</p><RoleBadges roles={u.roles} membershipActive={u.membership_status === 'ACTIVE'} /></>}</td><td className="px-3 py-2">{date(u.last_login_at)}</td><td className="px-3 py-2">{date(u.created_at)}</td><td className="px-3 py-2"><UserActionsMenu name={u.display_name || u.email} onView={() => { setDetail(null); setSelected(u); }} /></td></tr>)}</tbody></table>{!rows.length && <div className="py-10 px-6 text-center"><Users className="mx-auto mb-3 h-8 w-8 text-hcl-muted" aria-hidden="true" /><p className="font-semibold">No users found.</p><p className="mt-2 text-sm text-hcl-muted">{search || status || role || provider || tenantFilter ? 'Try adjusting your search or filters.' : 'Create a native user to allow local access to SBOM Analyzer.'}</p>{onAdd && (platform ? canGlobal : canInvite) && <button disabled={!(platform ? canGlobal : canInvite)} className="mt-4 text-link" onClick={onAdd}>+ Add User</button>}</div>}</div>}
    <div className="flex flex-wrap items-center justify-end gap-3 text-sm"><span className="mr-auto text-hcl-muted">Showing {total ? (page - 1) * 20 + 1 : 0}–{Math.min(page * 20, total)} of {total} users</span><button disabled={page === 1 || loading} onClick={() => { setLoading(true); setPage(p => p - 1); }}>Previous</button><span>Page {page} · {total} users</span><button disabled={page * 20 >= total || loading} onClick={() => { setLoading(true); setPage(p => p + 1); }}>Next</button></div>
    </>}
    {selected && !detail && !error && <p role="status">Loading user details…</p>}
    {detail && <article className="border rounded p-5 space-y-4" key={`${uid}:${revision}`}>
      <h2 tabIndex={-1} ref={node => { if (node && selected) node.focus(); }} className="text-xl font-semibold outline-none">{detail.display_name || detail.email}</h2><p>{detail.email} · {(detail.providers || []).map(providerLabel).join(' + ')}</p><UserStatusBadge status={detail.account_status} /><button className="float-right" onClick={() => { setSelected(null); setDetail(null); }}>Close details</button>
      <h3 className="font-semibold">Account security & authentication activity</h3><p>Email verified: {detail.email_verified ? 'Yes' : 'No'} · Last login: {detail.last_login_at || 'Never'}</p><p>Created: {detail.created_at} · Updated: {detail.updated_at}</p>
      {platform && detail.security && <p>Password last changed: {date(detail.security.password_changed_at)} · Failed logins: {detail.security.failed_login_count} · Locked until: {detail.security.locked_until || 'Not locked'}</p>}
      <h3 className="font-semibold">Profile</h3><p>{detail.first_name} {detail.last_name} · {detail.phone || 'No phone recorded'}</p><h3 className="font-semibold">Identity providers</h3><p>{detail.providers.map(providerLabel).join(' + ')}</p>
      {canProfile && <form className="flex flex-wrap gap-3" onSubmit={(e: FormEvent<HTMLFormElement>) => { e.preventDefault(); const data = new FormData(e.currentTarget); void mutate(`${prefix}/${identifier(detail)}/profile`, 'PATCH', Object.fromEntries(['first_name', 'last_name', 'phone'].map(k => [k, data.get(k)]))); }}>
        {['first_name', 'last_name', 'phone'].map(k => <label key={k}>{k.replace('_', ' ')} <input className={inputClass} name={k} defaultValue={detail[k as 'first_name'] || ''} maxLength={k === 'phone' ? 64 : 120} required={k !== 'phone'} /></label>)}<button disabled={busy}>{busy ? 'Saving…' : 'Save profile'}</button><p>Profile changes apply to this user across tenants. Email cannot be edited here.</p>
      </form>}
      {canGlobal && <div className="flex gap-4 flex-wrap">
        {detail.account_status === 'PENDING' && <button disabled={busy} onClick={() => confirm(`Approve ${detail.display_name}? Tenant memberships and roles must still be assigned separately.`, () => mutate(`/platform/users/${uid}/status`, 'PATCH', { status: 'ACTIVE' }))}>Approve account</button>}
        {detail.account_status === 'ACTIVE' && detail.providers.includes('MICROSOFT_ENTRA') && <button disabled={busy} onClick={() => confirm(`Suspend ${detail.display_name} globally? Access to all tenants will be blocked.`, () => mutate(`/platform/users/${uid}/status`, 'PATCH', { status: 'SUSPENDED' }))}>Suspend account globally</button>}
        {detail.account_status === 'SUSPENDED' && <button disabled={busy} onClick={() => confirm(`Resume ${detail.display_name}? Only active memberships regain access.`, () => mutate(`/platform/users/${uid}/status`, 'PATCH', { status: 'ACTIVE' }))}>Resume account</button>}
        {detail.account_status !== 'PENDING' && (detail.account_status !== 'DISABLED' ? <button disabled={busy} onClick={() => confirm(`Disable ${detail.display_name} globally? Access to every tenant will be blocked.`, () => mutate(`/platform/users/${uid}/status`, 'PATCH', { status: 'DISABLED' }))}>Disable account globally</button> : <button disabled={busy} onClick={() => confirm(`Enable ${detail.display_name} globally? Active tenant memberships may regain access.`, () => mutate(`/platform/users/${uid}/status`, 'PATCH', { status: 'ACTIVE' }))}>Enable account globally</button>)}
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
        {canInvite && detail.account_status === 'PENDING_EMAIL_VERIFICATION' && detail.providers.includes('NATIVE') && <button disabled={busy} onClick={() => confirm(`Resend activation to ${detail.display_name} for ${m.tenant_name}? The previous activation link will stop working.`, () => mutate(`${platform ? '/platform' : ''}/tenants/${m.tenant_id}/native-users/${uid}/resend-activation`, 'POST', undefined, platform ? null : m.tenant_id))}>Resend activation</button>}
      </section>)}
      {platform && canInvite && <form onSubmit={e => { e.preventDefault(); if (!newTenant) return; const data = new FormData(e.currentTarget); const tenant = Number(newTenant.id); void mutate(`/tenants/${tenant}/memberships`, 'POST', { user_id: uid, role_codes: data.getAll('roles') }, tenant); }}><h3>Add existing user to another tenant</h3><TenantSearchSelect value={newTenant} onChange={setNewTenant} />{roles.map(r => <label className="mr-3" key={r}><input type="checkbox" name="roles" value={r} defaultChecked={r === 'VIEWER'} /> {r}</label>)}<button disabled={busy || !newTenant}>Add membership</button></form>}
      <h3 id="audit" className="font-semibold">Recent audit activity</h3><ol aria-label="Audit timeline" className="border-l-2 pl-4 space-y-3">{detail.activity?.items.map(a => <li key={a.id}><time>{a.timestamp}</time><p className="capitalize font-medium">{readable(a.action)} · {a.outcome}</p><p className="text-sm">{a.tenant_id ? 'Tenant activity' : 'Account activity'}</p></li>)}</ol><p>{detail.activity?.total || 0} recorded events; showing the most recent 50.</p>
    </article>}
    <ConfirmationDialog open={Boolean(confirmation)} title="Confirm access change" description={confirmation?.text || ''} confirmLabel="Confirm" onClose={() => setConfirmation(null)} onConfirm={() => { const run = confirmation?.run; setConfirmation(null); if (run) void run(); }} />
  </section>;
}
