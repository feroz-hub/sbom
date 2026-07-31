import { Building2, Info, RefreshCw } from 'lucide-react';
import { MembershipStatusBadge } from './StatusBadges';
import { resolveIdentityMapping, type IdentityMappingInfo } from '@/lib/identityMapping';

interface TenantContextHeaderProps {
  name: string;
  slug: string;
  externalIamTenantId?: string | null;
  identityMapping?: IdentityMappingInfo | Record<string, unknown> | null;
  isPlatformAdmin?: boolean;
  isApiError?: boolean;
  onRetryMapping?: () => void;
  status: string;
  memberCount?: number;
  initialAdministrator?: string;
  currentAdministrators?: string[];
}

export function TenantContextHeader({
  name,
  slug,
  externalIamTenantId,
  identityMapping,
  isPlatformAdmin = false,
  isApiError = false,
  onRetryMapping,
  status,
  memberCount,
  initialAdministrator,
  currentAdministrators,
}: TenantContextHeaderProps) {
  const mapping = resolveIdentityMapping(identityMapping, externalIamTenantId, isApiError);

  return (
    <div className="rounded-xl border border-border bg-surface p-5 shadow-elev-1 space-y-3">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-hcl-blue/10 text-hcl-blue mt-0.5">
            <Building2 className="h-6 w-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold text-foreground">{name}</h1>
              <MembershipStatusBadge status={status} />
            </div>
            <div className="mt-1.5 flex flex-wrap items-center gap-3 text-xs text-hcl-muted">
              <span>Slug: <code className="font-mono text-foreground/90">{slug}</code></span>
              <span>•</span>
              <span className="inline-flex items-center gap-1.5">
                <span>Identity mode:</span>
                <span className="font-semibold text-foreground">{mapping.displayStatus}</span>
                {mapping.mode === 'LOCAL_ONLY' && (
                  <span
                    className="inline-flex items-center text-hcl-muted hover:text-foreground cursor-help"
                    title="Access is managed by SBOM tenant memberships and role assignments."
                    aria-label="Access is managed by SBOM tenant memberships and role assignments."
                  >
                    <Info className="h-3.5 w-3.5" />
                  </span>
                )}
                {mapping.mode === 'UNAVAILABLE' && onRetryMapping && (
                  <button
                    type="button"
                    onClick={onRetryMapping}
                    className="ml-1 inline-flex items-center gap-1 font-medium text-hcl-blue hover:underline text-xs"
                  >
                    <RefreshCw className="h-3 w-3" /> Retry
                  </button>
                )}
              </span>
              {typeof memberCount === 'number' && (
                <>
                  <span>•</span>
                  <span>{memberCount} member{memberCount === 1 ? '' : 's'}</span>
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

      {isPlatformAdmin && (
        <details className="mt-3 border-t border-border pt-3 text-xs text-hcl-muted">
          <summary className="cursor-pointer font-medium text-foreground hover:text-hcl-blue">
            Technical identity details
          </summary>
          <div className="mt-2 space-y-1 rounded-lg bg-surface-muted/50 p-2.5 font-mono text-[11px]">
            <div>Mode: {mapping.mode}</div>
            <div>Provider: {mapping.provider || 'None'}</div>
            <div>External IAM Tenant ID: {mapping.externalTenantId || 'None'}</div>
            <div>Verified: {String(mapping.verified)}</div>
            {mapping.isLegacy && <div>Legacy Flag: True</div>}
          </div>
        </details>
      )}
    </div>
  );
}

