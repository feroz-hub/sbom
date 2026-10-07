'use client';

import Link from 'next/link';
import { useQuery } from '@tanstack/react-query';
import {
  Activity,
  ArrowRight,
  Building2,
  CheckCircle2,
  Clock3,
  Cpu,
  Layers3,
  Plus,
  RefreshCw,
  ShieldCheck,
  ShieldAlert,
  UsersRound,
  CirclePause,
  type LucideIcon,
} from 'lucide-react';
import { useAuth } from '@/hooks/useAuth';
import { getPlatformSummary, listPlatformTenants } from '@/lib/api';
import { TopBar } from '@/components/layout/TopBar';
import { TenantStatusBadge } from '@/components/admin/StatusBadges';
import { cn } from '@/lib/utils';

const tenantsHref = '/settings/platform/tenants';
const focus =
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 focus-visible:ring-offset-surface';
const accents = {
  blue: 'bg-primary/10 text-primary dark:text-primary-300',
  green:
    'bg-emerald-50 text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-300',
  amber: 'bg-amber-50 text-amber-800 dark:bg-amber-950/40 dark:text-amber-300',
  neutral: 'bg-surface-muted text-foreground/70',
};
const metrics: Array<{
  key: string;
  title: string;
  icon: LucideIcon;
  tone: keyof typeof accents;
  description: string;
  zero?: string;
  permission?: string;
}> = [
  {
    key: 'total_tenants',
    title: 'Total Tenants',
    icon: Building2,
    tone: 'blue',
    description: 'Across the platform',
  },
  {
    key: 'active_tenants',
    title: 'Active Tenants',
    icon: CheckCircle2,
    tone: 'green',
    description: 'Enabled tenant workspaces',
    zero: 'No active tenants yet',
  },
  {
    key: 'disabled_tenants',
    title: 'Disabled Tenants',
    icon: CirclePause,
    tone: 'neutral',
    description: 'Tenant access disabled',
    zero: 'No disabled tenants',
  },
  {
    key: 'pending_tenants',
    title: 'Pending Setup',
    icon: Clock3,
    tone: 'amber',
    description: 'Awaiting administrator activation',
    zero: 'No pending tenant setup',
  },
  {
    key: 'total_memberships',
    title: 'Total Memberships',
    icon: UsersRound,
    tone: 'blue',
    description: 'Explicit tenant memberships',
  },
  {
    key: 'tenants_without_admin',
    title: 'Tenants Without Admin',
    icon: ShieldAlert,
    tone: 'amber',
    description: 'Administrator attention required',
    zero: 'All tenants have active administrators',
  },
  {
    key: 'platform_admins',
    title: 'Platform Administrators',
    icon: ShieldCheck,
    tone: 'blue',
    description: 'Platform governance access',
    permission: 'platform:administrator:read',
  },
];
const governance = [
  { title: 'Component Advisor Policies', description: 'Manage inherited risk, trust and scoring defaults', action: 'Configure', href: '/platform/configuration/advisor-policies', icon: ShieldCheck, permission: 'platform:advisor-policy:read' },
  {
    title: 'Tenant Administration',
    description: 'Create and manage tenant lifecycle',
    action: 'Open Tenants',
    href: tenantsHref,
    icon: Building2,
    permission: 'platform:tenant:read',
  },
  {
    title: 'AI Configuration',
    description: 'Manage platform-wide AI defaults',
    action: 'Configure',
    href: '/platform/configuration/ai',
    icon: Cpu,
    permission: 'platform:ai:read',
  },
  {
    title: 'Lifecycle Providers',
    description: 'Manage shared lifecycle provider defaults',
    action: 'Configure',
    href: '/platform/configuration/lifecycle',
    icon: Layers3,
    permission: 'platform:lifecycle-provider:read',
  },
  {
    title: 'Platform Administrators',
    description: 'Manage platform administrator access',
    action: 'Manage',
    href: '/settings/platform',
    icon: ShieldCheck,
    permission: 'platform:administrator:read',
  },
  {
    title: 'Platform Health',
    description: 'Review service and configuration health',
    action: 'View Health',
    href: '/settings/iam',
    icon: Activity,
    permission: 'platform:health:read',
  },
];
function dateLabel(value?: string) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? '—'
    : date.toLocaleDateString(undefined, {
        day: 'numeric',
        month: 'short',
        year: 'numeric',
      });
}

export default function PlatformDashboard() {
  const { user, hasPermission, isLoading } = useAuth();
  const allowed =
    user?.isPlatformAdmin === true && hasPermission('platform:tenant:read');
  const summary = useQuery({
    queryKey: ['platform-summary'],
    queryFn: getPlatformSummary,
    enabled: !isLoading && allowed,
  });
  const tenants = useQuery({
    queryKey: ['platform-tenants', 'overview'],
    queryFn: () => listPlatformTenants('', 1, 5),
    enabled: !isLoading && allowed,
  });
  if (isLoading) return <p>Verifying platform access…</p>;
  if (!allowed)
    return <p role="alert">Platform Administrator access is required.</p>;
  const refreshing = summary.isFetching || tenants.isFetching;
  const createAction = hasPermission('platform:tenant:create') && (
    <Link
      href={`${tenantsHref}#create-tenant`}
      className={cn(
        'inline-flex h-10 items-center justify-center gap-2 rounded-lg bg-[var(--btn-primary)] px-3 text-sm font-semibold text-white shadow-elev-1 hover:bg-[var(--btn-primary-hover)]',
        focus,
      )}
    >
      <Plus className="h-4 w-4" aria-hidden />
      Create Tenant
    </Link>
  );
  return (
    <div className="flex min-w-0 flex-1 flex-col">
      <TopBar
        title="Platform Dashboard"
        subtitle="Platform control plane"
        action={<div className="hidden md:block">{createAction}</div>}
      />
      <main className="mx-auto w-full min-w-0 max-w-[1440px] space-y-6 p-4 md:p-6 xl:p-8">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="text-sm text-foreground/70">
            Monitor tenant provisioning, platform configuration and governance.
          </p>
          <div className="flex items-center gap-2">
            <div className="md:hidden">{createAction}</div>
            <button
              type="button"
              disabled={refreshing}
              onClick={() => {
                void summary.refetch();
                void tenants.refetch();
              }}
              className={cn(
                'inline-flex h-10 items-center gap-2 rounded-lg border border-border bg-surface px-3 text-sm font-medium text-foreground hover:bg-surface-muted disabled:opacity-60',
                focus,
              )}
            >
              <RefreshCw
                className={cn(
                  'h-4 w-4',
                  refreshing && 'animate-spin motion-reduce:animate-none',
                )}
                aria-hidden
              />
              {refreshing ? 'Refreshing…' : 'Refresh'}
            </button>
          </div>
        </div>
        <aside
          aria-label="Platform overview"
          className="flex gap-3 rounded-xl border border-primary/15 bg-primary/5 px-4 py-3"
        >
          <ShieldCheck
            className="mt-0.5 h-4 w-4 shrink-0 text-primary dark:text-primary-300"
            aria-hidden
          />
          <div className="text-xs leading-relaxed">
            <span className="font-semibold text-foreground">
              Platform overview
            </span>
            <span className="ml-2 text-foreground/70">
              Manage tenant lifecycle, shared configuration and administrator
              governance. Tenant business data remains isolated.
            </span>
          </div>
        </aside>
        <section
          aria-label="Platform metrics"
          className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4"
        >
          {metrics
            .filter(
              (metric) =>
                !metric.permission || hasPermission(metric.permission),
            )
            .map((metric) => {
              const value = summary.data?.[metric.key];
              const Icon =
                metric.key === 'tenants_without_admin' && value === 0
                  ? CheckCircle2
                  : metric.icon;
              const tone =
                metric.key === 'tenants_without_admin' && value === 0
                  ? 'green'
                  : metric.tone;
              return (
                <article
                  key={metric.key}
                  className="flex min-h-40 flex-col rounded-2xl border border-border bg-surface p-5 shadow-elev-1 transition-shadow hover:shadow-elev-2 motion-reduce:transition-none"
                >
                  <div className="flex items-center gap-3">
                    <span
                      className={cn(
                        'flex h-9 w-9 shrink-0 items-center justify-center rounded-xl',
                        accents[tone],
                      )}
                    >
                      <Icon className="h-[18px] w-[18px]" aria-hidden />
                    </span>
                    <h2 className="text-sm font-medium text-foreground/70">
                      {metric.title}
                    </h2>
                  </div>
                  <p
                    className="mt-4 text-3xl font-semibold tracking-tight text-foreground tabular-nums"
                    aria-label={`${metric.title}: ${value ?? 'unavailable'}`}
                  >
                    {value === undefined ? '—' : value.toLocaleString()}
                  </p>
                  <p className="mt-1 text-xs leading-relaxed text-foreground/70">
                    {value === 0 && metric.zero
                      ? metric.zero
                      : metric.description}
                  </p>
                </article>
              );
            })}
        </section>
        {summary.error && (
          <div
            role="alert"
            className="rounded-xl border border-border bg-surface p-4 text-sm"
          >
            Unable to load platform metrics.{' '}
            <button
              onClick={() => void summary.refetch()}
              className={cn(
                'rounded font-semibold text-primary dark:text-primary-300 underline',
                focus,
              )}
            >
              Retry metrics
            </button>
          </div>
        )}
        <section
          aria-labelledby="tenant-overview-title"
          className="overflow-hidden rounded-2xl border border-border bg-surface shadow-elev-1"
        >
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-5 py-4">
            <div>
              <h2
                id="tenant-overview-title"
                className="font-semibold text-foreground"
              >
                Tenant Overview
              </h2>
              <p className="mt-1 text-xs text-foreground/70">
                Up to five tenants, ordered by name. Lifecycle and governance at
                a glance.
              </p>
            </div>
            <Link
              href={tenantsHref}
              className={cn(
                'inline-flex items-center gap-1.5 rounded text-sm font-medium text-primary dark:text-primary-300 hover:underline',
                focus,
              )}
            >
              View all tenants
              <ArrowRight className="h-4 w-4" aria-hidden />
            </Link>
          </div>
          {tenants.isLoading && (
            <p role="status" className="p-6 text-sm text-foreground/70">
              Loading tenant overview…
            </p>
          )}
          {tenants.error && (
            <div role="alert" className="p-6 text-sm">
              Unable to load tenant overview.{' '}
              <button
                onClick={() => void tenants.refetch()}
                className={cn(
                  'rounded font-medium text-primary dark:text-primary-300 underline',
                  focus,
                )}
              >
                Retry tenants
              </button>
            </div>
          )}
          {tenants.data &&
            !tenants.error &&
            (tenants.data.length === 0 ? (
              <div className="p-8 text-center">
                <Building2
                  className="mx-auto mb-3 h-8 w-8 text-foreground/70"
                  aria-hidden
                />
                <h3 className="font-semibold">No tenants yet</h3>
                <p className="mt-1 text-sm text-foreground/70">
                  Create your first tenant to begin provisioning its
                  administrator.
                </p>
                <div className="mt-4">{createAction}</div>
              </div>
            ) : (
              <div
                className="overflow-x-auto"
                role="region"
                aria-label="Tenant overview table"
                tabIndex={0}
              >
                <table className="w-full min-w-[640px] text-left text-sm">
                  <thead className="bg-surface-muted/70 text-xs text-foreground/70">
                    <tr>
                      {[
                        'Tenant',
                        'Status',
                        'Members',
                        'Tenant Admins',
                        'Created',
                        'Actions',
                      ].map((label) => (
                        <th
                          key={label}
                          scope="col"
                          className="px-5 py-3 font-medium"
                        >
                          {label}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {tenants.data.map((tenant) => (
                      <tr key={tenant.id} className="hover:bg-surface-muted/50">
                        <td className="px-5 py-4">
                          <p
                            className="max-w-64 truncate font-semibold text-foreground"
                            title={tenant.name}
                          >
                            {tenant.name}
                          </p>
                          <p className="mt-0.5 text-xs text-foreground/70">
                            {tenant.slug}
                          </p>
                        </td>
                        <td className="px-5 py-4">
                          <TenantStatusBadge status={tenant.status} />
                        </td>
                        <td className="px-5 py-4 tabular-nums">
                          {tenant.member_count ?? '—'}
                        </td>
                        <td className="px-5 py-4 tabular-nums">
                          {tenant.current_administrators?.length ?? '—'}
                        </td>
                        <td className="whitespace-nowrap px-5 py-4 text-xs text-foreground/70">
                          {dateLabel(tenant.created_at)}
                        </td>
                        <td className="px-5 py-4">
                          <Link
                            href={`${tenantsHref}/${tenant.id}`}
                            aria-label={`View ${tenant.name}`}
                            className={cn(
                              'inline-flex items-center gap-1 rounded-lg border border-border px-3 py-1.5 text-xs font-semibold text-foreground hover:bg-surface-muted',
                              focus,
                            )}
                          >
                            View
                            <ArrowRight className="h-3 w-3" aria-hidden />
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ))}
        </section>
        <section aria-labelledby="platform-governance-title">
          <h2
            id="platform-governance-title"
            className="mb-3 font-semibold text-foreground"
          >
            Platform Governance
          </h2>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {governance
              .filter((card) => hasPermission(card.permission))
              .map((card) => (
                <Link
                  key={card.href}
                  href={card.href}
                  className={cn(
                    'group flex min-w-0 items-start gap-3 rounded-xl border border-border bg-surface p-4 shadow-elev-1 transition-shadow hover:shadow-elev-2',
                    focus,
                  )}
                >
                  <span className="rounded-lg bg-primary/10 p-2 text-primary dark:text-primary-300">
                    <card.icon className="h-5 w-5" aria-hidden />
                  </span>
                  <div className="min-w-0 flex-1">
                    <h3 className="text-sm font-semibold text-foreground">
                      {card.title}
                    </h3>
                    <p className="mt-1 text-xs leading-relaxed text-foreground/70">
                      {card.description}
                    </p>
                    <span className="mt-3 inline-flex items-center gap-1 text-xs font-semibold text-primary dark:text-primary-300">
                      {card.action}
                      <ArrowRight className="h-3.5 w-3.5" aria-hidden />
                    </span>
                  </div>
                </Link>
              ))}
          </div>
        </section>
      </main>
    </div>
  );
}
