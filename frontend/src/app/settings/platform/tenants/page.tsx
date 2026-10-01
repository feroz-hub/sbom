'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { FormEvent, useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@/hooks/useAuth';
import {
  type CreateTenantRequest,
  type UserSearchResult,
  ApiError,
  createPlatformTenant,
  listPlatformTenants,
  updatePlatformTenantStatus,
} from '@/lib/api';
import { useNotifications } from '@/hooks/useNotifications';
import { getApiErrorMessage } from '@/lib/notifications';
import { ConfirmationDialog } from '@/components/ui/ConfirmationDialog';
import { slugFromName, validateTenantForm } from '@/lib/tenantForm';
import { TenantStatusBadge } from '@/components/admin/StatusBadges';
import { UserSearchCombobox } from '@/components/admin/UserSearchCombobox';
import { TopBar } from '@/components/layout/TopBar';

const EMPTY_FORM: CreateTenantRequest = {
  name: '',
  slug: '',
  initial_admin_user_id: 0,
};

function safeErrorMessage(error: unknown): string {
  if (!(error instanceof ApiError)) {
    return 'The tenant could not be created. Please try again or contact the platform administrator.';
  }
  if (error.status === 401) return 'Your session has expired. Please sign in again.';
  if (error.status === 403) return 'You do not have permission to create or manage tenants.';
  if (error.status === 409) {
    return error.message;
  }
  if (error.status === 422) {
    return error.message;
  }
  return 'The tenant could not be created. Please try again or contact the platform administrator.';
}

function validationErrorsFromResponse(error: unknown): Partial<Record<keyof CreateTenantRequest, string>> {
  if (!(error instanceof ApiError)) return {};
  if (
    error.code === 'IAM_TENANT_SLUG_CONFLICT'
    || error.code === 'TENANT_SLUG_ALREADY_EXISTS'
  ) {
    return { slug: error.message };
  }
  if (error.status !== 422 && !error.fieldErrors) return {};
  if (error.code === 'IAM_INITIAL_TENANT_ADMIN_REQUIRED') {
    return { initial_admin_user_id: 'Select an initial Tenant Administrator.' };
  }
  if (
    error.code === 'IAM_INITIAL_TENANT_ADMIN_NOT_FOUND'
    || error.code === 'IAM_ACCOUNT_DISABLED'
    || error.code === 'IAM_ACCOUNT_PENDING_APPROVAL'
    || error.code === 'IAM_EMAIL_VERIFICATION_REQUIRED'
  ) {
    return { initial_admin_user_id: error.message };
  }
  if (error.fieldErrors) {
    const mapped: Partial<Record<keyof CreateTenantRequest, string>> = {};
    for (const field of ['name', 'slug', 'initial_admin_user_id'] as const) {
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
    if (field === 'initial_admin_user_id') errors.initial_admin_user_id = 'Select an initial Tenant Administrator.';
  }
  return errors;
}

function formatDate(value?: string): string {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleDateString();
}

export default function PlatformTenantsPage() {
  const router = useRouter();
  const { hasPermission, isLoading: authLoading } = useAuth();
  const canManage = hasPermission('platform:tenant:create');
  const canRead = hasPermission('platform:tenant:read');
  const canStatus = hasPermission('platform:tenant:update_status');
  const queryClient = useQueryClient();
  const [formOpen, setFormOpen] = useState(false);
  useEffect(() => {
    if (canManage && window.location.hash === '#create-tenant') setFormOpen(true);
  }, [canManage]);
  const [form, setForm] = useState<CreateTenantRequest>(EMPTY_FORM);
  const [adminMode, setAdminMode] = useState<'existing' | 'invite'>('existing');
  const [tenantSearch, setTenantSearch] = useState('');
  const [tenantPage, setTenantPage] = useState(1);
  const [selectedInitialAdmin, setSelectedInitialAdmin] = useState<UserSearchResult | null>(null);
  const [slugEdited, setSlugEdited] = useState(false);
  const [fieldErrors, setFieldErrors] = useState<Partial<Record<keyof CreateTenantRequest, string>>>({});
  const { showSuccess, showError, showInfo } = useNotifications();
  const [disableTarget, setDisableTarget] = useState<{ id: number | string; name: string } | null>(null);

  const tenants = useQuery({
    queryKey: ['platform-tenants', tenantSearch, tenantPage],
    queryFn: () => listPlatformTenants(tenantSearch, tenantPage),
    enabled: !authLoading && canRead,
    retry: false,
  });

  const createTenant = useMutation({
    mutationFn: createPlatformTenant,
    onSuccess: async (tenant) => {
      showSuccess(`Tenant “${tenant.name}” was created successfully.`);
      setForm(EMPTY_FORM);
      setAdminMode('existing');
      setSlugEdited(false);
      setSelectedInitialAdmin(null);
      setFieldErrors({});
      setFormOpen(false);
      await queryClient.invalidateQueries({ queryKey: ['platform-tenants'] });
      router.push(`/settings/platform/tenants/${tenant.id}`);
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
      ...(adminMode === 'invite' ? { initial_admin_invitation: form.initial_admin_invitation }
        : { initial_admin_user_id: form.initial_admin_user_id }),
    };
    const errors = validateTenantForm(normalized);
    setFieldErrors(errors);
    if (Object.keys(errors).length > 0) return;
    createTenant.mutate(normalized);
  };

  const formIsValid = Object.keys(validateTenantForm(form)).length === 0;

  if (authLoading) {
    return <div className="p-8 text-center text-hcl-muted">Verifying platform permission…</div>;
  }
  if (!canRead) {
    return (
      <div role="alert" className="p-8 text-center text-red-700">
        You do not have permission to create or manage tenants.
      </div>
    );
  }

  return (
    <>
      <TopBar
        title="Platform Tenants"
        subtitle="Manage tenant provisioning, availability and administrator governance."
        action={canManage ? <button
          type="button"
          onClick={() => setFormOpen(true)}
          className="rounded-md bg-hcl-blue px-4 py-2 text-sm font-medium text-white hover:bg-hcl-blue/90 transition-colors"
        >
          Create Tenant
        </button> : undefined}
      />
    <div className="mx-auto w-full max-w-6xl space-y-6 p-6">

      <nav aria-label="Platform administration" className="flex gap-2 border-b border-border pb-3 text-sm">
        <Link href="/settings/platform" className="rounded-md px-3 py-2 font-medium text-hcl-blue hover:bg-surface-elevated">Administrators</Link>
        <Link href="/settings/platform/tenants" aria-current="page" className="rounded-md bg-hcl-blue px-3 py-2 font-medium text-white">Tenants</Link>
      </nav>

      {formOpen && (
        <section id="create-tenant" aria-labelledby="create-tenant-heading" className="scroll-mt-24 rounded-xl border border-border bg-surface p-5 shadow-elev-1">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h2 id="create-tenant-heading" className="text-lg font-semibold">Create tenant</h2>
              <p className="mt-1 text-sm text-hcl-muted">Create a tenant with its initial administrator. Invited administrators must activate their account before the tenant becomes active.</p>
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
            <label className="text-sm font-medium md:col-span-2">
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
            <div className="md:col-span-2">
              <label className="mb-1 block text-sm font-medium">Initial Tenant Administrator</label>
              <fieldset className="mb-4 flex gap-4"><legend className="sr-only">Administrator provisioning</legend>
                {(['existing', 'invite'] as const).map(mode => <label key={mode}>
                  <input type="radio" name="adminMode" checked={adminMode === mode} onChange={() => {
                    setAdminMode(mode);
                    setForm(current => ({ ...current, initial_admin_user_id: mode === 'existing' ? selectedInitialAdmin?.id ?? 0 : undefined,
                      initial_admin_invitation: mode === 'invite' ? { first_name: '', last_name: '', email: '', phone: '' } : undefined }));
                  }} /> {mode === 'existing' ? 'Select existing user' : 'Invite new user'}
                </label>)}
              </fieldset>
              {adminMode === 'existing' ? <UserSearchCombobox governance
                onSelect={(user) => {
                  setSelectedInitialAdmin(user);
                  setForm((current) => ({
                    ...current,
                    initial_admin_user_id: user?.id ?? 0,
                  }));
                }}
                selectedUser={selectedInitialAdmin}
                placeholder="Search existing SBOM users by email, display name, or username…"
                requireEligible
              /> : <div className="grid gap-3 md:grid-cols-2">
                {(['first_name', 'last_name', 'email', 'phone'] as const).map(field => <label key={field} className="capitalize">
                  {field.replace('_', ' ')}{field === 'phone' ? ' (optional)' : ' *'}
                  <input className="mt-1 w-full rounded-md border border-border bg-background px-3 py-2"
                    type={field === 'email' ? 'email' : 'text'} required={field !== 'phone'}
                    maxLength={field === 'email' ? 320 : field === 'phone' ? 64 : 120}
                    value={form.initial_admin_invitation?.[field] ?? ''}
                    onChange={event => setForm(current => ({ ...current,
                      initial_admin_invitation: { first_name: '', last_name: '', email: '', ...current.initial_admin_invitation, [field]: event.target.value },
                    }))} />
                </label>)}
              </div>}
              {fieldErrors.initial_admin_invitation && <p role="alert">{fieldErrors.initial_admin_invitation}</p>}
              {fieldErrors.initial_admin_user_id && (
                <span className="mt-1 block text-xs text-red-600">{fieldErrors.initial_admin_user_id}</span>
              )}
            </div>
            <div className="md:col-span-2 rounded-lg border border-border p-4">
              <h3 className="text-sm font-semibold">Review</h3>
              <dl className="mt-2 grid gap-1 text-sm md:grid-cols-[14rem_1fr]">
                <dt className="text-hcl-muted">Tenant</dt><dd>{form.name.trim() || '—'}</dd>
                <dt className="text-hcl-muted">Slug</dt><dd>{form.slug.trim() || '—'}</dd>
                <dt className="text-hcl-muted">Initial Tenant Administrator</dt>
                <dd>
                  {adminMode === 'invite' ? `${form.initial_admin_invitation?.first_name ?? ''} ${form.initial_admin_invitation?.last_name ?? ''} (${form.initial_admin_invitation?.email ?? ''})` : selectedInitialAdmin
                    ? `${selectedInitialAdmin.display_name || selectedInitialAdmin.username || 'Unnamed user'} (${selectedInitialAdmin.email || 'no email'})`
                    : '—'}
                </dd>
                <dt className="text-hcl-muted">Role</dt><dd>TENANT_ADMIN</dd>
              </dl>
            </div>
            <div className="md:col-span-2">
              <button
                type="submit"
                disabled={
                  createTenant.isPending
                  || !formIsValid
                }
                className="rounded-md bg-hcl-blue px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
              >
                {createTenant.isPending ? 'Creating…' : adminMode === 'invite' ? 'Create Tenant & Invite Admin' : 'Create Tenant'}
              </button>
            </div>
          </form>
        </section>
      )}

      <section aria-labelledby="tenant-list-heading" className="space-y-3">
        <div className="flex items-center justify-between gap-3">
          <h2 id="tenant-list-heading" className="text-lg font-semibold">Existing tenants</h2>
          <label className="text-sm">Search tenants<input className="ml-2 rounded border bg-background px-3 py-2"
            value={tenantSearch} onChange={event => { setTenantSearch(event.target.value); setTenantPage(1); }} /></label>
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
              <thead className="bg-surface-elevated border-b border-border">
                <tr>
                  <th className="px-4 py-3 text-left font-semibold">Name</th>
                  <th className="px-4 py-3 text-left font-semibold">Slug</th>
                  <th className="px-4 py-3 text-left font-semibold">Status</th>
                  <th className="px-4 py-3 text-left font-semibold">Members</th>
                  <th className="px-4 py-3 text-left font-semibold">Created</th>
                  <th className="px-4 py-3 text-right font-semibold">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {tenants.data.map((tenant) => (
                  <tr key={tenant.id} className="hover:bg-surface-elevated/50 transition-colors">
                    <td className="px-4 py-3 font-semibold">{tenant.name}</td>
                    <td className="px-4 py-3 font-mono text-xs text-hcl-muted">{tenant.slug}</td>
                    <td className="px-4 py-3"><TenantStatusBadge status={tenant.status} /></td>
                    <td className="px-4 py-3">{tenant.member_count ?? '—'}</td>
                    <td className="px-4 py-3 text-xs text-hcl-muted">{formatDate(tenant.created_at)}</td>
                    <td className="px-4 py-3 text-right space-x-3">
                      <Link
                        href={`/settings/platform/tenants/${tenant.id}`}
                        className="font-medium text-foreground hover:underline"
                      >
                        Manage
                      </Link>
                      {canStatus && (tenant.status === 'ACTIVE' ? (
                        <button
                          type="button"
                          className="text-red-700 hover:underline"
                          onClick={() => setDisableTarget({ id: tenant.id, name: tenant.name })}
                        >
                          Disable
                        </button>
                      ) : (
                        <button
                          type="button"
                          disabled={changeStatus.isPending}
                          className="text-emerald-700 hover:underline disabled:opacity-50"
                          onClick={() => changeStatus.mutate({ id: tenant.id, name: tenant.name, status: 'ACTIVE' })}
                        >
                          Enable
                        </button>
                      ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <div className="flex gap-3"><button disabled={tenantPage === 1} onClick={() => setTenantPage(tenantPage - 1)}>Previous tenants</button>
        <span>Page {tenantPage}</span><button disabled={(tenants.data?.length ?? 0) < 50} onClick={() => setTenantPage(tenantPage + 1)}>Next tenants</button></div>

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
    </>
  );
}
