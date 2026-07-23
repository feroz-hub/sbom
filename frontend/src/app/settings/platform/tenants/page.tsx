'use client';

import Link from 'next/link';
import { FormEvent, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@/hooks/useAuth';
import {
  type CreateTenantRequest,
  ApiError,
  createPlatformTenant,
  listPlatformTenants,
  updatePlatformTenantStatus,
} from '@/lib/api';
import { useNotifications } from '@/hooks/useNotifications';
import { getApiErrorMessage } from '@/lib/notifications';
import { ConfirmationDialog } from '@/components/ui/ConfirmationDialog';
import { slugFromName, validateTenantForm } from '@/lib/tenantForm';

const EMPTY_FORM: CreateTenantRequest = { name: '', slug: '', external_iam_tenant_id: '' };

function safeErrorMessage(error: unknown): string {
  if (!(error instanceof ApiError)) {
    return 'The tenant could not be created. Please try again or contact the platform administrator.';
  }
  if (error.status === 401) return 'Your session has expired. Please sign in again.';
  if (error.status === 403) return 'You do not have permission to create or manage tenants.';
  if (error.status === 409) {
    const message = error.message.toLowerCase();
    if (message.includes('external')) return 'A tenant with this external IAM tenant ID already exists.';
    return 'A tenant with this slug already exists.';
  }
  if (error.status === 422) return 'Review the highlighted fields and submit valid tenant information.';
  return 'The tenant could not be created. Please try again or contact the platform administrator.';
}

function validationErrorsFromResponse(error: unknown): Partial<Record<keyof CreateTenantRequest, string>> {
  if (!(error instanceof ApiError) || error.status !== 422) return {};
  if (error.fieldErrors) {
    const mapped: Partial<Record<keyof CreateTenantRequest, string>> = {};
    for (const field of ['name', 'slug', 'external_iam_tenant_id'] as const) {
      if (error.fieldErrors[field]?.[0]) mapped[field] = error.fieldErrors[field][0];
    }
    return mapped;
  }
  if (!Array.isArray(error.detail)) return {};
  const errors: Partial<Record<keyof CreateTenantRequest, string>> = {};
  for (const issue of error.detail as Array<{ loc?: Array<string | number>; msg?: string }>) {
    const field = issue.loc?.at(-1);
    if (field === 'name') errors.name = 'Enter a valid tenant name.';
    if (field === 'slug') errors.slug = 'Slug may contain lowercase letters, numbers, and single hyphens only.';
    if (field === 'external_iam_tenant_id') errors.external_iam_tenant_id = 'External IAM tenant ID is required.';
  }
  return errors;
}

function formatDate(value?: string): string {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString();
}

export default function PlatformTenantsPage() {
  const { hasPermission, isLoading: authLoading } = useAuth();
  const canManage = hasPermission('platform:tenant:create');
  const queryClient = useQueryClient();
  const [formOpen, setFormOpen] = useState(false);
  const [form, setForm] = useState<CreateTenantRequest>(EMPTY_FORM);
  const [slugEdited, setSlugEdited] = useState(false);
  const [fieldErrors, setFieldErrors] = useState<Partial<Record<keyof CreateTenantRequest, string>>>({});
  const { showSuccess, showError, showInfo } = useNotifications();
  const [disableTarget, setDisableTarget] = useState<{ id: number | string; name: string } | null>(null);
  const [highlightedTenantId, setHighlightedTenantId] = useState<number | string | null>(null);

  const tenants = useQuery({
    queryKey: ['platform-tenants'],
    queryFn: listPlatformTenants,
    enabled: !authLoading && canManage,
    retry: false,
  });

  const createTenant = useMutation({
    mutationFn: createPlatformTenant,
    onSuccess: async (tenant) => {
      setHighlightedTenantId(tenant.id);
      showSuccess(`Tenant “${tenant.name}” was created successfully.`);
      setForm(EMPTY_FORM);
      setSlugEdited(false);
      setFieldErrors({});
      setFormOpen(false);
      await queryClient.invalidateQueries({ queryKey: ['platform-tenants'] });
    },
    onError: (error) => {
      setFieldErrors(validationErrorsFromResponse(error));
      showError(safeErrorMessage(error));
    },
  });

  const changeStatus = useMutation({
    mutationFn: ({ id, status }: { id: number | string; name: string; status: 'ACTIVE' | 'DISABLED' }) =>
      updatePlatformTenantStatus(id, status),
    onSuccess: async (_result, variables) => {
      showSuccess(`Tenant “${variables.name}” was ${variables.status === 'ACTIVE' ? 'activated' : 'disabled'} successfully.`);
      setDisableTarget(null);
      await queryClient.invalidateQueries({ queryKey: ['platform-tenants'] });
    },
    onError: (error) => showError(getApiErrorMessage(error, 'The tenant status could not be changed.')),
  });

  const submit = (event: FormEvent) => {
    event.preventDefault();
    const normalized = {
      name: form.name.trim(),
      slug: form.slug.trim(),
      external_iam_tenant_id: form.external_iam_tenant_id.trim(),
    };
    const errors = validateTenantForm(normalized);
    setFieldErrors(errors);
    if (Object.keys(errors).length > 0) return;
    createTenant.mutate(normalized);
  };

  if (authLoading) {
    return <div className="p-8 text-center text-hcl-muted">Verifying platform permission…</div>;
  }
  if (!canManage) {
    return (
      <div role="alert" className="p-8 text-center text-red-700">
        You do not have permission to create or manage tenants.
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-6xl space-y-6 p-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">Platform tenants</h1>
          <p className="mt-1 max-w-3xl text-sm text-hcl-muted">
            Create and manage SBOM tenants. Each tenant must have a unique external IAM tenant ID matching the
            tenant_id claim issued by HCL.CS.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setFormOpen(true)}
          className="rounded-md bg-hcl-blue px-4 py-2 text-sm font-medium text-white"
        >
          Create Tenant
        </button>
      </div>

      <nav aria-label="Platform administration" className="flex gap-2 border-b border-border pb-3 text-sm">
        <Link href="/settings/platform" className="rounded-md px-3 py-2 font-medium text-hcl-blue hover:bg-surface-elevated">Administrators</Link>
        <Link href="/settings/platform/tenants" aria-current="page" className="rounded-md bg-hcl-blue px-3 py-2 font-medium text-white">Tenants</Link>
      </nav>

      {formOpen && (
        <section aria-labelledby="create-tenant-heading" className="rounded-xl border border-border bg-surface p-5 shadow-elev-1">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h2 id="create-tenant-heading" className="text-lg font-semibold">Create tenant</h2>
              <p className="mt-1 text-sm text-hcl-muted">This creates only the SBOM tenant. It does not create users, memberships, or platform grants.</p>
            </div>
            <button type="button" onClick={() => { setFormOpen(false); setFieldErrors({}); }} className="text-sm text-hcl-muted hover:underline">Cancel</button>
          </div>
          <form onSubmit={submit} className="mt-5 grid gap-4 md:grid-cols-2">
            <label className="text-sm font-medium md:col-span-2">
              Name
              <input
                aria-label="Name"
                aria-invalid={Boolean(fieldErrors.name)}
                value={form.name}
                maxLength={255}
                onChange={(event) => {
                  const name = event.target.value;
                  setForm((current) => ({ ...current, name, slug: slugEdited ? current.slug : slugFromName(name) }));
                }}
                className="mt-1 w-full rounded-md border border-border bg-background px-3 py-2"
                required
              />
              {fieldErrors.name && <span className="mt-1 block text-xs text-red-600">{fieldErrors.name}</span>}
            </label>
            <label className="text-sm font-medium">
              Slug
              <input
                aria-label="Slug"
                aria-invalid={Boolean(fieldErrors.slug)}
                value={form.slug}
                maxLength={128}
                onChange={(event) => { setSlugEdited(true); setForm((current) => ({ ...current, slug: event.target.value })); }}
                className="mt-1 w-full rounded-md border border-border bg-background px-3 py-2"
                required
              />
              <span className="mt-1 block text-xs text-hcl-muted">Preview: /tenants/{form.slug || 'tenant-slug'}</span>
              {fieldErrors.slug && <span className="mt-1 block text-xs text-red-600">{fieldErrors.slug}</span>}
            </label>
            <label className="text-sm font-medium">
              External IAM Tenant ID
              <input
                aria-label="External IAM Tenant ID"
                aria-invalid={Boolean(fieldErrors.external_iam_tenant_id)}
                value={form.external_iam_tenant_id}
                maxLength={255}
                onChange={(event) => setForm((current) => ({ ...current, external_iam_tenant_id: event.target.value }))}
                className="mt-1 w-full rounded-md border border-border bg-background px-3 py-2"
                required
              />
              <span className="mt-1 block text-xs text-hcl-muted">This value must match the tenant_id claim issued by HCL.CS for users belonging to this tenant.</span>
              {fieldErrors.external_iam_tenant_id && <span className="mt-1 block text-xs text-red-600">{fieldErrors.external_iam_tenant_id}</span>}
            </label>
            <div className="md:col-span-2">
              <button type="submit" disabled={createTenant.isPending} className="rounded-md bg-hcl-blue px-4 py-2 text-sm font-medium text-white disabled:opacity-50">
                {createTenant.isPending ? 'Creating…' : 'Create Tenant'}
              </button>
            </div>
          </form>
        </section>
      )}

      <section aria-labelledby="tenant-list-heading" className="space-y-3">
        <div className="flex items-center justify-between gap-3">
          <h2 id="tenant-list-heading" className="text-lg font-semibold">Existing tenants</h2>
          <button type="button" onClick={() => void tenants.refetch().then((result) => {
            if (result.error) showError(getApiErrorMessage(result.error, 'Tenant refresh failed.'));
            else showInfo('Tenant list refreshed.');
          })} disabled={tenants.isFetching} className="rounded-md border border-border px-3 py-1.5 text-sm disabled:opacity-50">
            {tenants.isFetching ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>
        {tenants.isLoading && <p className="text-sm text-hcl-muted">Loading tenants…</p>}
        {tenants.error && <p role="alert" className="text-sm text-red-700">{safeErrorMessage(tenants.error)}</p>}
        {tenants.data?.length === 0 && <div className="rounded-lg border border-dashed border-border p-8 text-center text-hcl-muted">No tenants have been created.</div>}
        {tenants.data && tenants.data.length > 0 && (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="min-w-full text-sm">
              <thead className="bg-surface-elevated">
                <tr>
                  <th className="px-4 py-2 text-left font-medium">Name</th>
                  <th className="px-4 py-2 text-left font-medium">Slug</th>
                  <th className="px-4 py-2 text-left font-medium">External IAM Tenant ID</th>
                  <th className="px-4 py-2 text-left font-medium">Status</th>
                  <th className="px-4 py-2 text-left font-medium">Created</th>
                  <th className="px-4 py-2 text-right font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {tenants.data.map((tenant) => (
                  <tr key={tenant.id} className={`border-t border-border ${tenant.id === highlightedTenantId ? 'bg-emerald-50 dark:bg-emerald-950/20' : ''}`}>
                    <td className="px-4 py-3 font-medium">{tenant.name}</td>
                    <td className="px-4 py-3 font-mono text-xs">{tenant.slug}</td>
                    <td className="px-4 py-3 font-mono text-xs">{tenant.external_iam_tenant_id}</td>
                    <td className="px-4 py-3">{tenant.status}</td>
                    <td className="px-4 py-3">{formatDate(tenant.created_at)}</td>
                    <td className="px-4 py-3 text-right">
                      {tenant.status === 'ACTIVE' ? (
                        <button
                          type="button"
                          className="text-red-700 hover:underline"
                          onClick={() => {
                            setDisableTarget({ id: tenant.id, name: tenant.name });
                          }}
                        >Disable</button>
                      ) : (
                        <button type="button" disabled={changeStatus.isPending} className="text-emerald-700 hover:underline disabled:opacity-50" onClick={() => changeStatus.mutate({ id: tenant.id, name: tenant.name, status: 'ACTIVE' })}>Activate</button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {highlightedTenantId !== null && (
        <div className="rounded-lg border border-blue-200 bg-blue-50 p-4 text-sm text-blue-900 dark:bg-blue-950/20 dark:text-blue-100">
          Create or configure the corresponding HCL.CS tenant_id claim, then add users through Tenant Settings.
        </div>
      )}
      <ConfirmationDialog
        open={disableTarget !== null}
        title={`Disable tenant “${disableTarget?.name ?? ''}”?`}
        description="Normal members will lose access on their next request. Existing data is retained."
        confirmLabel="Disable tenant"
        loading={changeStatus.isPending}
        onClose={() => !changeStatus.isPending && setDisableTarget(null)}
        onConfirm={() => disableTarget && changeStatus.mutate({ ...disableTarget, status: 'DISABLED' })}
      />
    </div>
  );
}
