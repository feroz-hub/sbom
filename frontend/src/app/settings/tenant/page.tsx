'use client';

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@/hooks/useAuth';
import { usePermission } from '@/hooks/usePermission';
import { BASE_URL, HttpError } from '@/lib/api';
import { getAccessToken, getActiveTenantId } from '@/lib/auth';

interface TenantUserRow {
  membership_id: number;
  user_id: number;
  external_iam_user_id: string;
  email: string | null;
  display_name: string | null;
  role: string;
  status: string;
}

async function fetchTenantUsers(tenantId: number): Promise<TenantUserRow[]> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const token = getAccessToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  const activeTenant = getActiveTenantId();
  if (activeTenant) headers['X-Tenant-ID'] = activeTenant;

  const res = await fetch(`${BASE_URL}/api/tenants/${tenantId}/users`, { headers });
  if (!res.ok) throw new HttpError('Failed to load tenant users', res.status);
  return res.json();
}

export default function TenantUsersPage() {
  const { user } = useAuth();
  const canRead = usePermission('tenant:user:read');
  const canManage = usePermission('tenant:user:update') || usePermission('tenant:user:invite');
  const tenantId = user?.tenantId ?? 1;
  const qc = useQueryClient();

  const { data, isLoading, error } = useQuery({
    queryKey: ['tenant-users', tenantId],
    queryFn: () => fetchTenantUsers(tenantId),
    enabled: canRead && tenantId > 0,
  });

  const disableMutation = useMutation({
    mutationFn: async (membershipId: number) => {
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      const token = getAccessToken();
      if (token) headers.Authorization = `Bearer ${token}`;
      const activeTenant = getActiveTenantId();
      if (activeTenant) headers['X-Tenant-ID'] = activeTenant;
      const res = await fetch(`${BASE_URL}/api/tenants/${tenantId}/users/${membershipId}`, {
        method: 'PATCH',
        headers,
        body: JSON.stringify({ status: 'DISABLED' }),
      });
      if (!res.ok) throw new HttpError('Failed to update user', res.status);
      return res.json();
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['tenant-users', tenantId] }),
  });

  if (!canRead) {
    return (
      <div className="p-8 text-center text-hcl-muted">
        You do not have permission to view tenant users.
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-4xl p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-foreground">Tenant users</h1>
        <p className="text-sm text-hcl-muted mt-1">
          Manage local membership and roles. Identity lifecycle is owned by HCL IAM.
        </p>
      </div>

      {isLoading && <p className="text-sm text-hcl-muted">Loading…</p>}
      {error && <p className="text-sm text-red-500">{(error as Error).message}</p>}

      {data && (
        <div className="overflow-hidden rounded-lg border border-border">
          <table className="min-w-full text-sm">
            <thead className="bg-surface-elevated">
              <tr>
                <th className="px-4 py-2 text-left font-medium">User</th>
                <th className="px-4 py-2 text-left font-medium">Role</th>
                <th className="px-4 py-2 text-left font-medium">Status</th>
                {canManage && <th className="px-4 py-2 text-right font-medium">Actions</th>}
              </tr>
            </thead>
            <tbody>
              {data.map((row) => (
                <tr key={row.membership_id} className="border-t border-border">
                  <td className="px-4 py-2">
                    <div className="font-medium">{row.display_name || row.external_iam_user_id}</div>
                    <div className="text-xs text-hcl-muted">{row.email}</div>
                  </td>
                  <td className="px-4 py-2">{row.role}</td>
                  <td className="px-4 py-2">{row.status}</td>
                  {canManage && (
                    <td className="px-4 py-2 text-right">
                      {row.status === 'ACTIVE' && (
                        <button
                          type="button"
                          className="text-xs text-red-600 hover:underline"
                          onClick={() => disableMutation.mutate(row.membership_id)}
                        >
                          Disable
                        </button>
                      )}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
