'use client';
import { Input } from '@/components/ui/Input';
import { Button } from '@/components/ui/Button';
import { useToast } from '@/hooks/useToast';
import styles from './NativeUsers.module.css';
import Link from 'next/link';
import { FormEvent, useState } from 'react';
import { useAuth } from '@/hooks/useAuth';
import { getActiveTenantId } from '@/lib/auth';
import { type TenantSummary } from '@/lib/api';
import { TenantSearchSelect } from './TenantSearchSelect';

export default function NativeUserInviteForm({ onCreated, onCancel, onBusyChange }: { onCreated?: () => void; onCancel?: () => void; onBusyChange?: (busy: boolean) => void }) {
  const { showToast } = useToast();
  const { hasPermission, activeTenantId, activeTenant } = useAuth();
  const platform = hasPermission('platform:user:manage_status');
  const allowed = platform || hasPermission('tenant:user:invite');
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const [selectedTenant, setSelectedTenant] = useState<TenantSummary | null>(null);
  const [conflictTenant, setConflictTenant] = useState<number | null>(null);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    setMessage('');
    const data = new FormData(event.currentTarget);
    const tenantId = Number(platform ? selectedTenant?.id : activeTenantId);
    if (!tenantId) { setMessage('Select an active tenant.'); return; }
    setConflictTenant(null);
    setBusy(true); onBusyChange?.(true);
    try {
      const selected = getActiveTenantId();
      const response = await fetch(`/api/backend/api/${platform ? 'platform/native-users' : `tenants/${tenantId}/native-users`}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', ...(selected ? { 'X-Tenant-ID': selected } : {}) },
        body: JSON.stringify({ first_name: data.get('first_name'), last_name: data.get('last_name'),
          email: data.get('email'), phone: data.get('phone'), tenant_id: tenantId, role_codes: data.getAll('role_codes') }),
      });
      const result = await response.json();
      if (result.detail?.code === 'MEMBERSHIP_ALREADY_EXISTS') {
        setConflictTenant(tenantId);
        setMessage(`This account already belongs to the selected tenant. Current roles: ${result.detail.roles.join(', ')}.`);
      } else {
        if (response.ok) {
          const delivery = result.delivery?.status;
          showToast(delivery === 'NOT_REQUIRED' ? 'Existing account added to the tenant.' : delivery === 'FAILED' ? 'User created, but activation email could not be delivered. Use resend activation to try again.' : 'Invitation created. The user will receive activation instructions.', delivery === 'FAILED' ? 'warning' : 'success');
          onCreated?.();
        } else setMessage('Unable to create user. Please review the information and selected tenant, then try again.');
      }
    } catch { setMessage('Unable to reach the server.'); }
    finally { setBusy(false); onBusyChange?.(false); }
  }
  if (!allowed) return <p className="p-8">Administrator permission is required.</p>;
  return <section className={`${styles.console} space-y-6`}>
    <p className="text-sm text-hcl-muted">Create a local SBOM Analyzer account and assign its access.</p>
    <p className="rounded-lg border border-border bg-surface-muted p-4 text-sm">The user sets their own password through an emailed activation link, valid for five hours.</p>
    <form onSubmit={submit} className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-2">{['first_name', 'last_name', 'email', 'phone'].map(name => <Input key={name} label={name.replace('_', ' ')} name={name} className="h-12" type={name === 'email' ? 'email' : name === 'phone' ? 'tel' : 'text'} required={name !== 'phone'} maxLength={name === 'email' ? 320 : name === 'phone' ? 64 : 120} />)}</div>
      {platform ? <TenantSearchSelect value={selectedTenant} onChange={setSelectedTenant} /> : <label className="block">Tenant<input className="block w-full rounded border p-2 bg-background" disabled readOnly value={activeTenant?.name ?? 'No active tenant'} /></label>}
      <fieldset className="space-y-2"><legend>Tenant roles</legend>
        {[...(platform ? ['TENANT_ADMIN'] : []), 'SECURITY_ANALYST', 'DEVELOPER', 'VIEWER'].map(role =>
          <label className="flex items-center gap-3 rounded-lg border border-border p-3 hover:bg-surface-muted" key={role}><input type="checkbox" name="role_codes" value={role} defaultChecked={role === 'VIEWER'} /> {role.replaceAll('_', ' ')}</label>)}
      </fieldset>
      <div className="flex justify-end gap-3 border-t border-border pt-5">{onCancel && <Button variant="secondary" disabled={busy} onClick={onCancel}>Cancel</Button>}<Button type="submit" loading={busy} disabled={!(platform ? selectedTenant : activeTenantId)}>{busy ? 'Creating user…' : 'Create and send invitation'}</Button></div>
    </form>{message && <p role="status">{message}</p>}
    {conflictTenant && <Link href={platform ? `/settings/platform/tenants/${conflictTenant}` : '/settings/users'}>Manage existing membership</Link>}
  </section>;
}
