'use client';

import { type RoleValue, getRoleLabel, getRoleCode } from '@/lib/roles';
import { cn } from '@/lib/utils';

export const ROLE_DESCRIPTIONS: Record<string, string> = {
  TENANT_ADMIN: 'Can manage tenant users, roles and tenant configuration.',
  SECURITY_ANALYST: 'Can review security findings, vulnerabilities, VEX and remediation information.',
  DEVELOPER: 'Can perform the project and SBOM operations allowed by the backend role policy.',
  VIEWER: 'Has read-only tenant access according to backend authorization policy.',
};

export function VerificationBadge({ verified }: { verified: boolean }) {
  if (verified) {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 px-2.5 py-0.5 text-xs font-medium text-emerald-700 dark:bg-emerald-950/20 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800/50">
        <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
        </svg>
        Verification: Verified
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-amber-50 px-2.5 py-0.5 text-xs font-medium text-amber-700 dark:bg-amber-950/20 dark:text-amber-400 border border-amber-200 dark:border-amber-800/50">
      <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m0 3.75h.008v.008H12v-.008z" />
      </svg>
      Verification: Verification required
    </span>
  );
}

export const ACCOUNT_STATUS_HELP: Record<string, string> = {
  ACTIVE: 'Account is active. Tenant access depends on membership and roles.',
  PENDING_EMAIL_VERIFICATION: 'User must verify their email and activate their account.',
  LOCKED: 'Account temporarily locked after failed authentication attempts.',
  DISABLED: 'Account disabled by an administrator.',
  FORCE_PASSWORD_CHANGE: 'User must replace their native password before normal access resumes.',
};
export function UserStatusBadge({ status }: { status: string }) {
  const label = (status || 'UNKNOWN').toLowerCase().replaceAll('_', ' ');
  return <span title={ACCOUNT_STATUS_HELP[status] || 'Account awaiting administration.'} className={cn('inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold', status === 'ACTIVE' ? 'bg-emerald-50 text-emerald-800 border-emerald-300' : status === 'DISABLED' ? 'bg-red-50 text-red-800 border-red-300' : 'bg-amber-50 text-amber-900 border-amber-300')}>User account: {label.charAt(0).toUpperCase() + label.slice(1)}</span>;
}

export function TenantStatusBadge({ status }: { status: string }) {
  const isActive = status?.toUpperCase() === 'ACTIVE';
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium border',
        isActive
          ? 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/20 dark:text-emerald-400 dark:border-emerald-800/50'
          : 'bg-zinc-100 text-zinc-600 border-zinc-200 dark:bg-zinc-800 dark:text-zinc-400 dark:border-zinc-700',
      )}
    >
      Tenant status: {isActive ? 'Active' : 'Disabled'}
    </span>
  );
}

export function MembershipStatusBadge({ status }: { status: string }) {
  const statusUpper = status?.toUpperCase();
  if (statusUpper === 'ACTIVE') {
    return (
      <span className="inline-flex items-center rounded-full bg-emerald-50 px-2.5 py-0.5 text-xs font-medium text-emerald-700 dark:bg-emerald-950/20 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800/50">
        Current membership: Active
      </span>
    );
  }
  if (statusUpper === 'PENDING') {
    return (
      <span className="inline-flex items-center rounded-full bg-amber-50 px-2.5 py-0.5 text-xs font-medium text-amber-700 dark:bg-amber-950/20 dark:text-amber-400 border border-amber-200 dark:border-amber-800/50">
        Current membership: Pending
      </span>
    );
  }
  return (
    <span className="inline-flex items-center rounded-full bg-zinc-100 px-2.5 py-0.5 text-xs font-medium text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400 border border-zinc-200 dark:border-zinc-700">
      Current membership: Disabled
    </span>
  );
}

export function RoleBadge({ role, active = true }: { role: RoleValue; active?: boolean }) {
  const label = getRoleLabel(role);
  const code = getRoleCode(role);
  const description = code ? ROLE_DESCRIPTIONS[code] : undefined;

  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold transition-colors cursor-help',
        active
          ? 'bg-hcl-blue/10 text-hcl-blue border border-hcl-blue/20 dark:bg-hcl-blue/20 dark:text-blue-300'
          : 'bg-zinc-100 text-zinc-400 border border-zinc-200 line-through opacity-60 dark:bg-zinc-800/40 dark:text-zinc-500 dark:border-zinc-700',
      )}
      title={description || label}
      aria-label={`${label} role (${active ? 'effective' : 'disabled'})${description ? `: ${description}` : ''}`}
    >
      {label}
    </span>
  );
}

export function RoleBadges({
  roles,
  membershipActive = true,
}: {
  roles?: RoleValue[] | null;
  membershipActive?: boolean;
}) {
  if (!membershipActive) {
    return <span className="text-xs text-hcl-muted font-medium">No effective roles</span>;
  }
  if (!roles || roles.length === 0) {
    return <span className="text-xs text-hcl-muted font-medium">No effective roles</span>;
  }
  return (
    <div className="flex flex-wrap items-center gap-1.5" aria-label="Tenant roles">
      {roles.map((r, i) => (
        <RoleBadge key={typeof r === 'object' ? String(r?.id ?? i) : String(r)} role={r} active={true} />
      ))}
    </div>
  );
}
