'use client';

import { useId, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Building2,
  ShieldCheck,
  ShieldHalf,
  SlidersHorizontal,
} from 'lucide-react';
import { usePermissions } from '@/hooks/usePermission';
import { useAuth } from '@/hooks/useAuth';
import { TopBar } from '@/components/layout/TopBar';
import { Button } from '@/components/ui/Button';
import { getAdvisorPolicy } from '@/lib/advisorPolicyApi';
import { PolicyEditor } from './advisor-policies/PolicyEditor';
import {
  definitions,
  type PolicyDefinition,
} from './advisor-policies/policyRules';
import styles from './advisor-policies/policies.module.css';

const icons = [ShieldHalf, ShieldCheck, SlidersHorizontal];

function PolicyPanel({
  tenantId,
  definition,
  canUpdate,
}: {
  tenantId: number | null;
  definition: PolicyDefinition;
  canUpdate: boolean;
}) {
  const query = useQuery({
    queryKey: ['advisor-policy', tenantId, definition.kind],
    queryFn: () => getAdvisorPolicy(tenantId, definition.kind),
    retry: false,
  });
  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-xl font-semibold text-hcl-navy">
          {definition.title}
        </h2>
        <p className="mt-2 max-w-4xl text-sm leading-6 text-hcl-muted">
          {definition.description}
        </p>
      </div>
      {query.isPending && (
        <div
          role="status"
          className="animate-pulse rounded-xl border border-border bg-surface p-6 text-sm text-hcl-muted"
        >
          Loading policy…
        </div>
      )}
      {query.isError && (
        <div
          role="alert"
          className="rounded-xl border border-border bg-surface p-5 text-sm"
        >
          Unable to load policy: {query.error.message}{' '}
          <Button variant="secondary" onClick={() => query.refetch()}>
            Retry
          </Button>
        </div>
      )}
      {query.data && (
        <PolicyEditor
          tenantId={tenantId}
          definition={definition}
          state={query.data}
          canUpdate={canUpdate}
          reload={async () => {
            const result = await query.refetch();
            if (result.error) throw result.error;
            return result.data!;
          }}
        />
      )}
    </div>
  );
}

function PolicyConsole({
  tenantId,
  canUpdate,
}: {
  tenantId: number | null;
  canUpdate: boolean;
}) {
  const [selected, setSelected] = useState(0);
  const tabs = useRef<(HTMLButtonElement | null)[]>([]);
  const id = useId();
  return (
    <div className="space-y-6">
      <div
        className="flex flex-wrap items-center justify-between gap-3 border-b border-border"
        role="tablist"
        aria-label="Advisor policy types"
      >
        {definitions.map((definition, index) => {
          const Icon = icons[index];
          return (
            <button
              key={definition.kind}
              ref={(element) => {
                tabs.current[index] = element;
              }}
              role="tab"
              type="button"
              id={`${id}-tab-${index}`}
              aria-controls={`${id}-panel-${index}`}
              aria-selected={selected === index}
              tabIndex={selected === index ? 0 : -1}
              onClick={() => setSelected(index)}
              onKeyDown={(event) => {
                const next =
                  event.key === 'ArrowRight'
                    ? (index + 1) % definitions.length
                    : event.key === 'ArrowLeft'
                      ? (index + definitions.length - 1) % definitions.length
                      : event.key === 'Home'
                        ? 0
                        : event.key === 'End'
                          ? definitions.length - 1
                          : null;
                if (next !== null) {
                  event.preventDefault();
                  setSelected(next);
                  tabs.current[next]?.focus();
                }
              }}
              className={`flex min-h-12 items-center gap-2 rounded-t-lg border-b-2 px-3 py-3 text-sm font-medium sm:px-5 ${selected === index ? 'border-primary bg-surface text-hcl-navy' : 'border-transparent text-hcl-muted hover:bg-surface-muted'}`}
            >
              <Icon className="h-4 w-4" aria-hidden />
              {definition.title}
            </button>
          );
        })}
      </div>
      {definitions.map((definition, index) => (
        <div
          key={definition.kind}
          role="tabpanel"
          id={`${id}-panel-${index}`}
          aria-labelledby={`${id}-tab-${index}`}
          hidden={selected !== index}
          tabIndex={0}
          className="min-w-0 rounded focus-visible:outline-primary"
        >
          <PolicyPanel
            tenantId={tenantId}
            definition={definition}
            canUpdate={canUpdate}
          />
        </div>
      ))}
    </div>
  );
}

export function ScopedAdvisorPolicies({
  scope,
}: {
  scope: 'platform' | 'tenant';
}) {
  const { activeTenantId, activeTenant, isLoading, isTenantContextLoading } =
    useAuth();
  const { can: hasPermission } = usePermissions();
  if (isLoading || isTenantContextLoading)
    return <p role="status">Verifying configuration access…</p>;
  if (
    (scope === 'tenant' && !activeTenantId) ||
    !hasPermission(`${scope}:advisor-policy:read`)
  )
    return (
      <p role="alert">
        Policy configuration access is not permitted in this context.
      </p>
    );
  const tenantId = scope === 'platform' ? null : Number(activeTenantId);
  const scopeName =
    scope === 'platform'
      ? 'platform defaults'
      : (activeTenant?.name ?? 'the active tenant');
  return (
    <div
      className={`${styles.page} flex min-w-0 flex-1 flex-col text-hcl-navy`}
    >
      <TopBar
        title="Component Advisor Policies"
        subtitle="Configure accepted risk, trust criteria and recommendation scoring."
        breadcrumbs={[
          {
            label: scope === 'platform' ? 'Platform' : 'Settings',
            href: scope === 'platform' ? '/platform' : '/settings',
          },
          { label: 'Configuration' },
          { label: 'Component Advisor Policies' },
        ]}
      />
      <div className="mx-auto w-full max-w-7xl space-y-6 p-4 md:p-6 xl:p-8">
        <div className="flex flex-wrap items-start justify-between gap-3 rounded-xl border border-border bg-surface p-4 sm:p-5">
          <div className="flex min-w-0 items-start gap-3">
            <Building2
              className="mt-0.5 h-5 w-5 shrink-0 text-hcl-blue"
              aria-hidden
            />
            <div>
              <p className="break-words text-sm font-semibold">
                Configuration for {scopeName}
              </p>
              <p className="mt-1 text-sm leading-6 text-hcl-muted">
                {scope === 'platform'
                  ? 'Platform defaults apply to tenants that inherit. Tenant overrides remain independent.'
                  : 'Tenant policies can inherit the platform default, use their own rules, or disable inheritance.'}{' '}
                Every published change creates a new version and preserves
                history.
              </p>
            </div>
          </div>
        </div>
        <PolicyConsole
          key={`${scope}:${tenantId}`}
          tenantId={tenantId}
          canUpdate={hasPermission(`${scope}:advisor-policy:update`)}
        />
      </div>
    </div>
  );
}
