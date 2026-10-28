import { Building2, ShieldCheck, ChevronDown } from 'lucide-react';
import { MembershipStatusBadge, TenantStatusBadge } from './StatusBadges';

interface TenantContextHeaderProps {
  name: string;
  slug: string;
  tenantStatus?: string;
  membershipStatus?: string;
  authProvider?: string;
  memberCount?: number;
  initialAdministrator?: string;
  currentAdministrators?: string[];
  /** Backward compatibility props (ignored for rendering) */
  externalIamTenantId?: string | null;
  identityMapping?: unknown;
  isPlatformAdmin?: boolean;
  isApiError?: boolean;
  onRetryMapping?: () => void;
  status?: string;
}

export function TenantContextHeader({
  name,
  slug,
  tenantStatus,
  membershipStatus = 'ACTIVE',
  memberCount,
  initialAdministrator,
  currentAdministrators,
  status,
}: TenantContextHeaderProps) {
  const effectiveTenantStatus = tenantStatus || status || 'ACTIVE';

  return (
    <div className="rounded-xl border border-border bg-surface p-4 sm:px-5 shadow-elev-1 space-y-3">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex min-w-0 items-start gap-3.5">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-hcl-blue/10 text-hcl-blue mt-0.5">
            <Building2 className="h-5 w-5" aria-hidden="true" />
          </div>
          <div className="min-w-0 space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="break-words text-lg font-semibold text-foreground">{name}</h2>
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="inline-flex items-center gap-1 text-xs text-hcl-muted">Tenant: <TenantStatusBadge status={effectiveTenantStatus} /></span>
                <MembershipStatusBadge status={membershipStatus} />
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2.5 text-xs text-hcl-muted">
              <span>
                Slug: <code className="break-all font-mono text-foreground/90">{slug}</code>
              </span>
              {typeof memberCount === 'number' && (
                <>
                  <span>•</span>
                  <span>
                    {memberCount} member{memberCount === 1 ? '' : 's'}
                  </span>
                </>
              )}
              {initialAdministrator && (
                <>
                  <span>•</span>
                  <span>Initial Tenant Administrator: {initialAdministrator}</span>
                </>
              )}
              {currentAdministrators && currentAdministrators.length > 0 && (
                <>
                  <span>•</span>
                  <span>Current Tenant Administrators: {currentAdministrators.join(', ')}</span>
                </>
              )}
            </div>
          </div>
        </div>
      </div>

      {(effectiveTenantStatus !== 'ACTIVE' || membershipStatus !== 'ACTIVE') && (
        <p role="alert" className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-800 dark:border-amber-900/50 dark:bg-amber-950/20 dark:text-amber-300">
          {effectiveTenantStatus !== 'ACTIVE' && <span className="block">This tenant is not active. Tenant access may be unavailable.</span>}
          {membershipStatus !== 'ACTIVE' && <span className="block">Your membership is not active. Assigned roles do not grant effective tenant access.</span>}
        </p>
      )}
    </div>
  );
}

export function TenantAccessInformation({ authProvider }: { authProvider?: string }) {
  return (
    <details className="group rounded-xl border border-border bg-surface shadow-elev-1">
      <summary className="flex min-h-16 cursor-pointer list-none items-center gap-3 rounded-xl px-5 py-4 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue [&::-webkit-details-marker]:hidden">
        <ShieldCheck className="h-5 w-5 shrink-0 text-hcl-blue" aria-hidden="true" />
        <h2 className="flex-1 text-base font-semibold text-foreground">Access Information</h2>
        <ChevronDown className="h-4 w-4 text-hcl-muted transition-transform group-open:rotate-180" aria-hidden="true" />
      </summary>
      <dl className="grid gap-5 border-t border-border px-5 py-4 text-sm sm:grid-cols-2">
        <div>
          <dt className="font-semibold text-foreground">Authentication</dt>
          <dd className="mt-1 leading-6 text-hcl-muted">{authProvider || 'Sign-in uses the method configured for your account: HCL.CS, a native account or Microsoft Entra.'}</dd>
        </div>
        <div>
          <dt className="font-semibold text-foreground">Tenant access</dt>
          <dd className="mt-1 leading-6 text-hcl-muted"><span className="text-foreground">Managed in SBOM.</span> Access depends on tenant membership and assigned roles. Email verification and user account status are shown separately in the directory.</dd>
        </div>
      </dl>
    </details>
  );
}
