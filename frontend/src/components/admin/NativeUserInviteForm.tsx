'use client';
import { FormEvent, useState } from 'react';
import { useAuth } from '@/hooks/useAuth';
import { getActiveTenantId } from '@/lib/auth';

export default function NativeUserInviteForm() {
  const { hasPermission, activeTenantId, user } = useAuth();
  const platform = hasPermission('platform:user:manage_status');
  const allowed = platform || hasPermission('tenant:user:invite');
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const tenantId = platform ? Number(data.get('tenant_id')) : Number(activeTenantId || user?.tenantId);
    setBusy(true);
    try {
      const selected = getActiveTenantId();
      const response = await fetch(`/api/backend/api/${platform ? 'platform/native-users' : `tenants/${tenantId}/native-users`}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', ...(selected ? { 'X-Tenant-ID': selected } : {}) },
        body: JSON.stringify({ first_name: data.get('first_name'), last_name: data.get('last_name'),
          email: data.get('email'), phone: data.get('phone'), tenant_id: tenantId, role_codes: data.getAll('role_codes') }),
      });
      const result = await response.json();
      setMessage(response.ok ? `Account ${result.user_id} created. Activation delivery: ${result.delivery.status}.` :
        typeof result.detail === 'string' ? result.detail : 'Unable to create account. Check the fields and selected tenant.');
    } catch { setMessage('Unable to reach the server.'); }
    finally { setBusy(false); }
  }
  if (!allowed) return <p className="p-8">Administrator permission is required.</p>;
  return <section className="max-w-xl mx-auto p-8 space-y-6">
    <h2 className="text-2xl font-semibold">Invite native user</h2>
    <p>The user will receive an activation link valid for five hours.</p>
    <form onSubmit={submit} className="space-y-4">
      {['first_name', 'last_name', 'email', 'phone'].map(name => <label className="block capitalize" key={name}>{name.replace('_', ' ')}
        <input className="block w-full rounded border p-2 bg-background" name={name} type={name === 'email' ? 'email' : 'text'} required maxLength={name === 'phone' ? 64 : 120} /></label>)}
      {platform && <label className="block">Tenant ID<input className="block w-full rounded border p-2 bg-background" name="tenant_id" type="number" min="1" required /></label>}
      <fieldset className="space-y-2"><legend>Tenant roles</legend>
        {[...(platform ? ['TENANT_ADMIN'] : []), 'SECURITY_ANALYST', 'DEVELOPER', 'VIEWER'].map(role =>
          <label className="block" key={role}><input type="checkbox" name="role_codes" value={role} defaultChecked={role === 'VIEWER'} /> {role.replaceAll('_', ' ')}</label>)}
      </fieldset>
      <button className="rounded bg-hcl-blue text-white px-4 py-2" disabled={busy}>{busy ? 'Creating…' : 'Create and send invitation'}</button>
    </form><p role="status">{message}</p>
  </section>;
}
