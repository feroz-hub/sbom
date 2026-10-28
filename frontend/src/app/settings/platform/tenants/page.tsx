'use client';

import Link from 'next/link';
import {
  ArrowLeft,
  ArrowRight,
  Building2,
  Plus,
  RefreshCw,
  Search,
  Users,
  X,
} from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { Dialog, DialogBody } from '@/components/ui/Dialog';
import styles from './tenants.module.css';
import { useRouter } from 'next/navigation';
import { FormEvent, useEffect, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { usePermissions } from '@/hooks/usePermission';
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
import { invalidatePlatformTenantSurfaces } from '@/lib/queryInvalidation';

const EMPTY_FORM: CreateTenantRequest = {
  name: '',
  slug: '',
  initial_admin_user_id: '',
};

function safeErrorMessage(error: unknown): string {
  if (!(error instanceof ApiError)) {
    return 'The tenant could not be created. Please try again or contact the platform administrator.';
  }
  if (error.status === 401)
    return 'Your session has expired. Please sign in again.';
  if (error.status === 403)
    return 'You do not have permission to create or manage tenants.';
  if (error.status === 409) {
    return error.message;
  }
  if (error.status === 422) {
    return error.message;
  }
  return 'The tenant could not be created. Please try again or contact the platform administrator.';
}

function validationErrorsFromResponse(
  error: unknown,
): Partial<Record<keyof CreateTenantRequest, string>> {
  if (!(error instanceof ApiError)) return {};
  if (
    error.code === 'IAM_TENANT_SLUG_CONFLICT' ||
    error.code === 'TENANT_SLUG_ALREADY_EXISTS'
  ) {
    return { slug: error.message };
  }
  if (error.status !== 422 && !error.fieldErrors) return {};
  if (error.code === 'IAM_INITIAL_TENANT_ADMIN_REQUIRED') {
    return { initial_admin_user_id: 'Select an initial Tenant Administrator.' };
  }
  if (
    error.code === 'IAM_INITIAL_TENANT_ADMIN_NOT_FOUND' ||
    error.code === 'IAM_ACCOUNT_DISABLED' ||
    error.code === 'IAM_ACCOUNT_PENDING_APPROVAL' ||
    error.code === 'IAM_EMAIL_VERIFICATION_REQUIRED'
  ) {
    return { initial_admin_user_id: error.message };
  }
  if (error.fieldErrors) {
    const mapped: Partial<Record<keyof CreateTenantRequest, string>> = {};
    for (const field of [
      'name',
      'slug',
      'initial_admin_user_id',
      'initial_admin_invitation',
    ] as const) {
      if (error.fieldErrors[field]?.[0])
        mapped[field] = error.fieldErrors[field][0];
    }
    const invitationErrors = Object.entries(error.fieldErrors)
      .filter(([key]) => key.startsWith('initial_admin_invitation.'))
      .flatMap(([, messages]) => messages);
    if (invitationErrors.length)
      mapped.initial_admin_invitation = invitationErrors.join(' ');
    return mapped;
  }
  if (!Array.isArray(error.detail)) return {};
  const errors: Partial<Record<keyof CreateTenantRequest, string>> = {};
  for (const issue of error.detail as Array<{
    loc?: Array<string | number>;
    msg?: string;
  }>) {
    const field = issue.loc?.at(-1);
    if (issue.loc?.includes('initial_admin_invitation'))
      errors.initial_admin_invitation =
        issue.msg || 'Check the administrator invitation details.';
    if (field === 'name') errors.name = 'Enter a valid tenant name.';
    if (field === 'slug')
      errors.slug =
        'Slug may contain lowercase letters, numbers, and single hyphens only.';
    if (field === 'initial_admin_user_id')
      errors.initial_admin_user_id = 'Select an initial Tenant Administrator.';
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
  const { isLoading: authLoading } = useAuth();
  const { can: hasPermission } = usePermissions();
  const canManage = hasPermission('platform:tenant:create');
  const canRead = hasPermission('platform:tenant:read');
  const canStatus = hasPermission('platform:tenant:update_status');
  const queryClient = useQueryClient();
  const [formOpen, setFormOpen] = useState(false);
  useEffect(() => {
    const openFromHash = () => {
      if (canManage && window.location.hash === '#create-tenant')
        setFormOpen(true);
    };
    openFromHash();
    window.addEventListener('hashchange', openFromHash);
    return () => window.removeEventListener('hashchange', openFromHash);
  }, [canManage]);
  const [form, setForm] = useState<CreateTenantRequest>(EMPTY_FORM);
  const [adminMode, setAdminMode] = useState<'existing' | 'invite'>('existing');
  const [tenantSearch, setTenantSearch] = useState('');
  const [directory, setDirectory] = useState({ query: '', page: 1 });
  const { query: debouncedSearch, page: tenantPage } = directory;
  const searching = tenantSearch.trim() !== debouncedSearch;
  useEffect(() => {
    const timer = setTimeout(
      () =>
        setDirectory((current) =>
          current.query === tenantSearch.trim()
            ? current
            : { query: tenantSearch.trim(), page: 1 },
        ),
      300,
    );
    return () => clearTimeout(timer);
  }, [tenantSearch]);
  const createLock = useRef(false);
  const statusLock = useRef(false);
  const [selectedInitialAdmin, setSelectedInitialAdmin] =
    useState<UserSearchResult | null>(null);
  const [slugEdited, setSlugEdited] = useState(false);
  const [fieldErrors, setFieldErrors] = useState<
    Partial<Record<keyof CreateTenantRequest, string>>
  >({});
  const { showSuccess, showError, showInfo } = useNotifications();
  const [disableTarget, setDisableTarget] = useState<{
    id: number | string;
    name: string;
  } | null>(null);

  const tenants = useQuery({
    queryKey: ['platform-tenants', debouncedSearch, tenantPage],
    queryFn: () => listPlatformTenants(debouncedSearch, tenantPage),
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
      await invalidatePlatformTenantSurfaces(queryClient, tenant.id);
      router.push(`/settings/platform/tenants/${tenant.id}`);
    },
    onSettled: () => {
      createLock.current = false;
    },
    onError: (error) => {
      setFieldErrors(validationErrorsFromResponse(error));
      showError(safeErrorMessage(error));
    },
  });

  const changeStatus = useMutation({
    mutationFn: ({
      id,
      status,
    }: {
      id: number | string;
      name: string;
      status: 'ACTIVE' | 'DISABLED';
    }) => updatePlatformTenantStatus(id, status),
    onSuccess: async (_result, variables) => {
      showSuccess(
        `Tenant “${variables.name}” was ${variables.status === 'ACTIVE' ? 'activated' : 'disabled'} successfully.`,
      );
      setDisableTarget(null);
      await invalidatePlatformTenantSurfaces(queryClient, variables.id);
    },
    onError: (error) =>
      showError(
        getApiErrorMessage(error, 'The tenant status could not be changed.'),
      ),
    onSettled: () => {
      statusLock.current = false;
    },
  });

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!canManage || createLock.current || createTenant.isPending) return;
    const normalized = {
      name: form.name.trim(),
      slug: form.slug.trim(),
      ...(adminMode === 'invite'
        ? { initial_admin_invitation: form.initial_admin_invitation }
        : { initial_admin_user_id: form.initial_admin_user_id }),
    };
    const errors = validateTenantForm(normalized);
    setFieldErrors(errors);
    if (Object.keys(errors).length > 0) return;
    createLock.current = true;
    createTenant.mutate(normalized);
  };

  const changeTenantStatus = (target: {
    id: number | string;
    name: string;
    status: 'ACTIVE' | 'DISABLED';
  }) => {
    if (!canStatus || statusLock.current || changeStatus.isPending) return;
    statusLock.current = true;
    changeStatus.mutate(target);
  };
  const closeForm = () => {
    if (!createTenant.isPending) {
      setFormOpen(false);
      setFieldErrors({});
    }
  };
  const clearSearch = () => {
    setTenantSearch('');
    setDirectory({ query: '', page: 1 });
  };
  const localErrors = validateTenantForm(form);
  const visibleErrors = {
    ...Object.fromEntries(
      Object.entries(localErrors).filter(
        ([key]) => key === 'slug' && slugEdited,
      ),
    ),
    ...fieldErrors,
  };
  const formIsValid = Object.keys(validateTenantForm(form)).length === 0;

  if (authLoading) {
    return (
      <div className="p-8 text-center text-hcl-muted">
        Verifying platform permission…
      </div>
    );
  }
  if (!canRead) {
    return (
      <div role="alert" className="p-8 text-center text-red-700">
        You do not have permission to create or manage tenants.
      </div>
    );
  }

  return (
    <div className={`${styles.page} min-w-0`}>
      <TopBar
        title="Platform Tenants"
        subtitle="Manage tenant provisioning, availability and administrator governance."
        breadcrumbs={[
          { label: 'Platform', href: '/settings/platform' },
          { label: 'Tenants' },
        ]}
        action={
          canManage ? (
            <button
              type="button"
              aria-label="Create Tenant"
              onClick={() => setFormOpen(true)}
              className="inline-flex min-h-10 items-center gap-2 rounded-lg bg-primary px-3 py-2 text-sm font-medium text-white"
            >
              <Plus className="h-4 w-4" aria-hidden />
              <span className="hidden sm:inline">Create Tenant</span>
              <span className="sm:hidden">Create</span>
            </button>
          ) : undefined
        }
      />
      <div className="mx-auto w-full max-w-7xl min-w-0 space-y-6 p-4 md:p-6 xl:p-8">
        <nav
          aria-label="Platform administration"
          className="flex flex-wrap gap-1 border-b border-border text-sm"
        >
          <Link
            href="/settings/platform"
            className="flex min-h-12 items-center gap-2 rounded-t-lg border-b-2 border-transparent px-4 font-medium text-hcl-muted hover:bg-surface-muted"
          >
            <Users className="h-4 w-4" aria-hidden />
            Administrators
          </Link>
          <Link
            href="/settings/platform/tenants"
            aria-current="page"
            className="flex min-h-12 items-center gap-2 rounded-t-lg border-b-2 border-primary bg-surface px-4 font-semibold text-hcl-navy"
          >
            <Building2 className="h-4 w-4" aria-hidden />
            Tenants
          </Link>
        </nav>

        <Dialog
          open={formOpen && canManage}
          onClose={closeForm}
          title="Create tenant"
          maxWidth="xl"
          dismissOnBackdrop={!createTenant.isPending}
        >
          <DialogBody className={styles.page}>
            <section
              id="create-tenant"
              aria-label="Create tenant form"
              className="space-y-5"
            >
              <p className="text-sm leading-6 text-hcl-muted">
                Create a tenant with its initial administrator. Invited
                administrators must activate their account before the tenant
                becomes active.
              </p>
              <form noValidate onSubmit={submit} className="space-y-6">
                <fieldset
                  disabled={createTenant.isPending}
                  className="min-w-0 space-y-6"
                >
                  <div className="space-y-4">
                    <h3 className="font-semibold text-hcl-navy">
                      Tenant details
                    </h3>
                    <label className="block text-sm font-medium">
                      Name
                      <input
                        aria-label="Name"
                        aria-invalid={Boolean(visibleErrors.name)}
                        aria-describedby={
                          visibleErrors.name ? 'tenant-name-error' : undefined
                        }
                        value={form.name}
                        onBlur={() =>
                          setFieldErrors((current) => ({
                            ...current,
                            name: validateTenantForm(form).name,
                          }))
                        }
                        maxLength={255}
                        onChange={(event) => {
                          setFieldErrors((current) => ({
                            ...current,
                            name: undefined,
                            slug: undefined,
                          }));
                          const name = event.target.value;
                          setForm((current) => ({
                            ...current,
                            name,
                            slug: slugEdited
                              ? current.slug
                              : slugFromName(name),
                          }));
                        }}
                        className="mt-1 w-full rounded-md border border-border bg-surface px-3 py-2 text-hcl-navy"
                        required
                      />
                      {visibleErrors.name && (
                        <span
                          id="tenant-name-error"
                          role="alert"
                          className="mt-1 block text-xs text-red-700 dark:text-red-300"
                        >
                          {visibleErrors.name}
                        </span>
                      )}
                    </label>
                    <label className="block text-sm font-medium">
                      Slug
                      <input
                        aria-label="Slug"
                        aria-invalid={Boolean(visibleErrors.slug)}
                        aria-describedby={
                          visibleErrors.slug ? 'tenant-slug-error' : undefined
                        }
                        value={form.slug}
                        onBlur={() =>
                          setFieldErrors((current) => ({
                            ...current,
                            slug: validateTenantForm(form).slug,
                          }))
                        }
                        maxLength={128}
                        onChange={(event) => {
                          setFieldErrors((current) => ({
                            ...current,
                            slug: undefined,
                          }));
                          setSlugEdited(true);
                          setForm((current) => ({
                            ...current,
                            slug: event.target.value,
                          }));
                        }}
                        className="mt-1 w-full rounded-md border border-border bg-surface px-3 py-2 text-hcl-navy"
                        required
                      />
                      <span className="mt-1 block text-xs text-hcl-muted">
                        Preview: /tenants/{form.slug || 'tenant-slug'}
                      </span>
                      {visibleErrors.slug && (
                        <span
                          id="tenant-slug-error"
                          role="alert"
                          className="mt-1 block text-xs text-red-700 dark:text-red-300"
                        >
                          {visibleErrors.slug}
                        </span>
                      )}
                    </label>
                  </div>
                  <div className="space-y-3 border-t border-border pt-5">
                    <h3 className="font-semibold text-hcl-navy">
                      Initial administrator
                    </h3>
                    <p className="text-sm text-hcl-muted">
                      Select an eligible user or send an account activation
                      invitation.
                    </p>
                    <p className="mb-1 text-sm font-medium">
                      Initial Tenant Administrator
                    </p>
                    <fieldset className="mb-4 flex flex-wrap gap-4">
                      <legend className="sr-only">
                        Administrator provisioning
                      </legend>
                      {(['existing', 'invite'] as const).map((mode) => (
                        <label key={mode}>
                          <input
                            type="radio"
                            name="adminMode"
                            checked={adminMode === mode}
                            onChange={() => {
                              setFieldErrors((current) => ({
                                ...current,
                                initial_admin_user_id: undefined,
                                initial_admin_invitation: undefined,
                              }));
                              setAdminMode(mode);
                              setForm((current) => ({
                                ...current,
                                initial_admin_user_id:
                                  mode === 'existing'
                                    ? (selectedInitialAdmin?.id ?? '')
                                    : undefined,
                                initial_admin_invitation:
                                  mode === 'invite'
                                    ? {
                                        first_name: '',
                                        last_name: '',
                                        email: '',
                                        phone: '',
                                      }
                                    : undefined,
                              }));
                            }}
                          />{' '}
                          {mode === 'existing'
                            ? 'Select existing user'
                            : 'Invite new user'}
                        </label>
                      ))}
                    </fieldset>
                    {adminMode === 'existing' ? (
                      <UserSearchCombobox
                        governance
                        onSelect={(user) => {
                          setFieldErrors((current) => ({
                            ...current,
                            initial_admin_user_id: undefined,
                          }));
                          setSelectedInitialAdmin(user);
                          setForm((current) => ({
                            ...current,
                            initial_admin_user_id: user?.id ?? '',
                          }));
                        }}
                        selectedUser={selectedInitialAdmin}
                        placeholder="Search existing SBOM users by email, display name, or username…"
                        requireEligible
                      />
                    ) : (
                      <div className="grid gap-3 sm:grid-cols-2">
                        {(
                          ['first_name', 'last_name', 'email', 'phone'] as const
                        ).map((field) => (
                          <label key={field} className="capitalize">
                            {field.replace('_', ' ')}
                            {field === 'phone' ? ' (optional)' : ' *'}
                            <input
                              className="mt-1 w-full rounded-md border border-border bg-surface px-3 py-2 text-hcl-navy"
                              type={
                                field === 'email'
                                  ? 'email'
                                  : field === 'phone'
                                    ? 'tel'
                                    : 'text'
                              }
                              onBlur={() =>
                                setFieldErrors((current) => ({
                                  ...current,
                                  initial_admin_invitation:
                                    validateTenantForm(form)
                                      .initial_admin_invitation,
                                }))
                              }
                              required={field !== 'phone'}
                              maxLength={
                                field === 'email'
                                  ? 320
                                  : field === 'phone'
                                    ? 64
                                    : 120
                              }
                              value={
                                form.initial_admin_invitation?.[field] ?? ''
                              }
                              onChange={(event) =>
                                setForm((current) => ({
                                  ...current,
                                  initial_admin_invitation: {
                                    first_name: '',
                                    last_name: '',
                                    email: '',
                                    ...current.initial_admin_invitation,
                                    [field]: event.target.value,
                                  },
                                }))
                              }
                            />
                          </label>
                        ))}
                      </div>
                    )}
                    {fieldErrors.initial_admin_invitation && (
                      <p role="alert">{fieldErrors.initial_admin_invitation}</p>
                    )}
                    {fieldErrors.initial_admin_user_id && (
                      <span className="mt-1 block text-xs text-red-700 dark:text-red-300">
                        {fieldErrors.initial_admin_user_id}
                      </span>
                    )}
                  </div>
                  <div className="rounded-lg border border-border bg-surface-muted p-4">
                    <h3 className="text-sm font-semibold">Review</h3>
                    <dl className="mt-2 grid gap-x-3 gap-y-2 text-sm sm:grid-cols-[9rem_minmax(0,1fr)]">
                      <dt className="text-hcl-muted">Tenant</dt>
                      <dd className="break-words">{form.name.trim() || '—'}</dd>
                      <dt className="text-hcl-muted">Slug</dt>
                      <dd className="break-words">{form.slug.trim() || '—'}</dd>
                      <dt className="text-hcl-muted">
                        Initial Tenant Administrator
                      </dt>
                      <dd className="break-words">
                        {adminMode === 'invite'
                          ? `${form.initial_admin_invitation?.first_name ?? ''} ${form.initial_admin_invitation?.last_name ?? ''} (${form.initial_admin_invitation?.email ?? ''})`
                          : selectedInitialAdmin
                            ? `${selectedInitialAdmin.display_name || selectedInitialAdmin.username || 'Unnamed user'} (${selectedInitialAdmin.email || 'no email'})`
                            : '—'}
                      </dd>
                      <dt className="text-hcl-muted">Role</dt>
                      <dd className="break-words">TENANT_ADMIN</dd>
                    </dl>
                  </div>
                  <div className="flex flex-wrap justify-end gap-3 border-t border-border pt-4">
                    <Button variant="secondary" onClick={closeForm}>
                      Cancel
                    </Button>
                    <button
                      type="submit"
                      disabled={createTenant.isPending || !formIsValid}
                      className="rounded-md bg-hcl-blue px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
                    >
                      {createTenant.isPending
                        ? 'Creating…'
                        : adminMode === 'invite'
                          ? 'Create Tenant & Invite Admin'
                          : 'Create Tenant'}
                    </button>
                  </div>
                </fieldset>
              </form>
            </section>
          </DialogBody>
        </Dialog>

        <section
          aria-labelledby="tenant-list-heading"
          className="min-w-0 overflow-hidden rounded-xl border border-border bg-surface shadow-card"
        >
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border p-5 sm:p-6">
            <div>
              <h2
                id="tenant-list-heading"
                className="text-lg font-semibold text-hcl-navy"
              >
                Tenant directory
              </h2>
              <p className="mt-1 text-sm text-hcl-muted">
                Find tenants, manage access and review their administrators.
              </p>
            </div>
          </div>
          <div className="flex flex-wrap items-end gap-3 border-b border-border bg-surface-muted p-4 sm:px-6">
            <label
              className="flex min-w-0 flex-1 flex-col gap-2 text-sm font-medium text-hcl-navy"
              htmlFor="tenant-search"
            >
              Search tenants
              <span className="relative block">
                <Search
                  className="pointer-events-none absolute left-3 top-3 h-4 w-4 text-hcl-muted"
                  aria-hidden
                />
                <input
                  id="tenant-search"
                  type="search"
                  placeholder="Search by tenant name or slug"
                  className="min-h-10 w-full rounded-lg border border-border bg-surface pl-10 pr-11 text-sm text-hcl-navy"
                  value={tenantSearch}
                  onChange={(event) => setTenantSearch(event.target.value)}
                />
                {tenantSearch && (
                  <button
                    type="button"
                    aria-label="Clear search"
                    onClick={clearSearch}
                    className="absolute right-0 top-0 flex h-10 w-10 items-center justify-center rounded-r-lg text-hcl-muted hover:bg-surface-muted"
                  >
                    <X className="h-4 w-4" aria-hidden />
                  </button>
                )}
              </span>
            </label>
            <Button
              variant="secondary"
              disabled={tenants.isFetching || searching}
              onClick={() =>
                void tenants.refetch().then((result) => {
                  if (result.error)
                    showError(
                      getApiErrorMessage(
                        result.error,
                        'Tenant refresh failed.',
                      ),
                    );
                  else showInfo('Tenant list refreshed.');
                })
              }
            >
              <RefreshCw
                className={`h-4 w-4 ${tenants.isFetching ? 'animate-spin' : ''}`}
                aria-hidden
              />
              {tenants.isFetching ? 'Refreshing…' : 'Refresh'}
            </Button>
          </div>
          <div
            aria-live="polite"
            className="border-b border-border-subtle px-5 py-3 text-sm text-hcl-muted"
          >
            {searching
              ? 'Updating search…'
              : tenants.isFetching
                ? 'Loading tenants…'
                : tenants.error
                  ? 'Tenant list could not be refreshed.'
                  : `${tenants.data?.length ?? 0} tenants on page ${tenantPage}${debouncedSearch ? ` matching “${debouncedSearch}”` : ''}.`}
          </div>
          {tenants.error && (
            <div
              role="alert"
              className="m-5 rounded-lg border border-red-300 bg-red-50 p-4 text-sm text-red-800 dark:border-red-800 dark:bg-red-950 dark:text-red-200"
            >
              <p>
                Unable to load tenants.{' '}
                {getApiErrorMessage(tenants.error, 'Please try again.')}
              </p>
              <Button
                variant="secondary"
                className="mt-3"
                disabled={tenants.isFetching || searching}
                onClick={() => tenants.refetch()}
              >
                Retry
              </Button>
            </div>
          )}
          {!tenants.isFetching &&
            !tenants.error &&
            tenants.data?.length === 0 && (
              <div className="m-5 rounded-xl border border-dashed border-border p-6 text-center sm:p-10">
                <Building2
                  className="mx-auto mb-3 h-8 w-8 text-hcl-muted"
                  aria-hidden
                />
                <h3 className="font-semibold text-hcl-navy">
                  {tenantPage > 1
                    ? 'No more tenants on this page.'
                    : debouncedSearch
                      ? 'No matching tenants.'
                      : 'No tenants have been created.'}
                </h3>
                <p className="mt-2 text-sm text-hcl-muted">
                  {tenantPage > 1
                    ? 'Return to the previous page to continue browsing.'
                    : debouncedSearch
                      ? 'Try another name or slug, or clear your search.'
                      : 'Create a tenant and assign its initial administrator to get started.'}
                </p>
                {debouncedSearch && (
                  <Button
                    variant="secondary"
                    className="mt-4"
                    onClick={clearSearch}
                  >
                    Clear search
                  </Button>
                )}
              </div>
            )}
          {tenants.data && tenants.data.length > 0 && (
            <div
              role="region"
              aria-label="Tenant directory table"
              tabIndex={0}
              className="overflow-x-auto"
              aria-busy={tenants.isFetching}
            >
              <table className="w-full min-w-[800px] text-left text-sm">
                <caption className="sr-only">
                  Platform tenants on page {tenantPage}
                </caption>
                <thead className="border-b border-border bg-surface-muted text-xs uppercase tracking-wide text-hcl-muted">
                  <tr>
                    {[
                      'Tenant name',
                      'Tenant slug',
                      'Status',
                      'Members',
                      'Created date',
                      'Actions',
                    ].map((label) => (
                      <th
                        key={label}
                        scope="col"
                        className={`px-5 py-4 font-semibold ${label === 'Actions' ? 'text-right' : label === 'Members' ? 'text-right' : ''}`}
                      >
                        {label}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle">
                  {tenants.data.map((tenant) => (
                    <tr
                      key={tenant.id}
                      className="transition-colors hover:bg-surface-muted"
                    >
                      <td className="px-5 py-4">
                        <div className="flex items-center gap-3">
                          <span
                            aria-hidden
                            className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-border bg-surface-muted text-xs font-semibold text-hcl-navy"
                          >
                            {tenant.name
                              .trim()
                              .split(/\s+/)
                              .slice(0, 2)
                              .map((word) => word[0])
                              .join('')
                              .toUpperCase() || '—'}
                          </span>
                          <span className="max-w-xs break-words font-semibold text-hcl-navy">
                            {tenant.name || 'Unnamed tenant'}
                          </span>
                        </div>
                      </td>
                      <td className="max-w-[220px] break-words px-5 py-4 font-mono text-xs text-hcl-muted">
                        {tenant.slug || '—'}
                      </td>
                      <td className="px-5 py-4">
                        <TenantStatusBadge status={tenant.status} />
                      </td>
                      <td className="px-5 py-4 text-right tabular-nums text-hcl-navy">
                        {tenant.member_count?.toLocaleString() ?? (
                          <span aria-label="Member count unavailable">—</span>
                        )}
                      </td>
                      <td className="whitespace-nowrap px-5 py-4 text-sm text-hcl-muted">
                        {formatDate(tenant.created_at) === '—' ? (
                          <span aria-label="Created date unavailable">—</span>
                        ) : (
                          <time
                            dateTime={tenant.created_at}
                            title={tenant.created_at}
                          >
                            {formatDate(tenant.created_at)}
                          </time>
                        )}
                      </td>
                      <td className="px-5 py-4">
                        <div className="flex items-center justify-end gap-2">
                          <Link
                            href={`/settings/platform/tenants/${tenant.id}`}
                            aria-label={`Manage ${tenant.name}`}
                            className="inline-flex h-10 items-center justify-center rounded-lg border border-border px-3 text-sm font-medium text-hcl-navy transition-colors hover:bg-surface-muted"
                          >
                            Manage
                          </Link>
                          {canStatus && (
                            <button
                              type="button"
                              className={`inline-flex h-10 transform-none items-center justify-center rounded-lg border bg-surface px-3 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${
                                tenant.status === 'ACTIVE'
                                  ? 'border-red-300 text-red-700 hover:bg-red-50 active:bg-red-100 dark:border-red-800 dark:text-red-300 dark:hover:bg-red-950 dark:active:bg-red-900'
                                  : 'border-emerald-300 text-emerald-700 hover:bg-emerald-50 active:bg-emerald-100 dark:border-emerald-800 dark:text-emerald-300 dark:hover:bg-emerald-950 dark:active:bg-emerald-900'
                              }`}
                              disabled={changeStatus.isPending}
                              aria-label={`${tenant.status === 'ACTIVE' ? 'Disable' : 'Enable'} ${tenant.name}`}
                              onClick={() =>
                                tenant.status === 'ACTIVE'
                                  ? setDisableTarget({
                                      id: tenant.id,
                                      name: tenant.name,
                                    })
                                  : changeTenantStatus({
                                      id: tenant.id,
                                      name: tenant.name,
                                      status: 'ACTIVE',
                                    })
                              }
                            >
                              {tenant.status === 'ACTIVE'
                                ? 'Disable'
                                : 'Enable'}
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <nav
            aria-label="Tenant pagination"
            className="flex flex-wrap items-center justify-between gap-3 border-t border-border bg-surface-muted px-5 py-4"
          >
            <p className="text-sm text-hcl-muted">
              Page{' '}
              <span className="font-semibold text-hcl-navy">{tenantPage}</span>{' '}
              · Up to 50 tenants per page
            </p>
            <div className="flex gap-2">
              <Button
                variant="secondary"
                disabled={tenantPage === 1 || tenants.isFetching || searching}
                onClick={() =>
                  setDirectory((current) => ({
                    ...current,
                    page: current.page - 1,
                  }))
                }
              >
                <ArrowLeft className="h-4 w-4" aria-hidden />
                Previous tenants
              </Button>
              <Button
                variant="secondary"
                disabled={
                  tenants.isFetching ||
                  searching ||
                  Boolean(tenants.error) ||
                  (tenants.data?.length ?? 0) < 50
                }
                onClick={() =>
                  setDirectory((current) => ({
                    ...current,
                    page: current.page + 1,
                  }))
                }
              >
                Next tenants
                <ArrowRight className="h-4 w-4" aria-hidden />
              </Button>
            </div>
          </nav>
        </section>

        <ConfirmationDialog
          open={disableTarget !== null}
          title={`Disable tenant “${disableTarget?.name ?? ''}”?`}
          description="Normal members will lose access on their next request. Existing data is retained."
          confirmLabel="Disable tenant"
          loading={changeStatus.isPending}
          onClose={() => !changeStatus.isPending && setDisableTarget(null)}
          onConfirm={() =>
            disableTarget &&
            changeTenantStatus({ ...disableTarget, status: 'DISABLED' })
          }
        />
      </div>
    </div>
  );
}
