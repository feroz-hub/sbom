import { Building2, Info } from 'lucide-react';
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
  authProvider = 'HCL.CS',
  memberCount,
  initialAdministrator,
  currentAdministrators,
  status,
}: TenantContextHeaderProps) {
  const effectiveTenantStatus = tenantStatus || status || 'ACTIVE';

  return (
    <div className="rounded-xl border border-border bg-surface p-5 shadow-elev-1 space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex items-start gap-3.5">
          <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-hcl-blue/10 text-hcl-blue mt-0.5">
            <Building2 className="h-6 w-6" />
          </div>
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="text-xl font-bold text-foreground">{name}</h1>
              <div className="flex flex-wrap items-center gap-1.5">
                <TenantStatusBadge status={effectiveTenantStatus} />
                <MembershipStatusBadge status={membershipStatus} />
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2.5 text-xs text-hcl-muted">
              <span>
                Slug: <code className="font-mono text-foreground/90">{slug}</code>
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

      <div className="grid gap-3 text-xs grid-cols-1 md:grid-cols-2">
        <div className="rounded-xl border border-border bg-surface-muted/60 p-4 space-y-1 transition-colors">
          <div className="flex items-center justify-between gap-2">
            <span className="font-semibold text-hcl-muted uppercase tracking-wider text-[11px]">Authentication</span>
            <span
              className="inline-flex items-center text-hcl-muted hover:text-foreground cursor-help"
              title="Your identity is authenticated by HCL.CS."
              aria-label="Your identity is authenticated by HCL.CS."
            >
              <Info className="h-3.5 w-3.5" />
            </span>
          </div>
          <div className="text-base font-bold text-foreground">{authProvider}</div>
          <p className="text-xs text-hcl-muted">User identity is verified by HCL.CS.</p>
        </div>

        <div className="rounded-xl border border-border bg-surface-muted/60 p-4 space-y-1 transition-colors">
          <div className="flex items-center justify-between gap-2">
            <span className="font-semibold text-hcl-muted uppercase tracking-wider text-[11px]">Tenant access</span>
            <span
              className="inline-flex items-center text-hcl-muted hover:text-foreground cursor-help"
              title="Access is controlled by SBOM tenant memberships and assigned roles."
              aria-label="Access is controlled by SBOM tenant memberships and assigned roles."
            >
              <Info className="h-3.5 w-3.5" />
            </span>
          </div>
          <div className="text-base font-bold text-foreground">Managed in SBOM</div>
          <p className="text-xs text-hcl-muted">Controlled by memberships and tenant roles.</p>
        </div>
      </div>
    </div>
  );
}
