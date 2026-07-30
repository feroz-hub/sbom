'use client';

import { type RoleValue, getRoleLabel } from '@/lib/roles';
import { cn } from '@/lib/utils';

export function VerificationBadge({ verified }: { verified: boolean }) {
  if (verified) {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:bg-emerald-950/20 dark:text-emerald-400">
        <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
        </svg>
        Verified
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-amber-50 px-2 py-0.5 text-xs font-medium text-amber-700 dark:bg-amber-950/20 dark:text-amber-400">
      <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m0 3.75h.008v.008H12v-.008z" />
      </svg>
      Verification Required
    </span>
  );
}

export function UserStatusBadge({ status }: { status: string }) {
  const isEnabled = status === 'ACTIVE';
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium',
        isEnabled
          ? 'bg-blue-50 text-blue-700 dark:bg-blue-950/20 dark:text-blue-400'
          : 'bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400',
      )}
    >
      {isEnabled ? 'Active' : 'Disabled'}
    </span>
  );
}

export function MembershipStatusBadge({ status }: { status: string }) {
  if (status === 'ACTIVE') {
    return (
      <span className="inline-flex items-center rounded-full bg-emerald-50 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:bg-emerald-950/20 dark:text-emerald-400">
        Active
      </span>
    );
  }
  if (status === 'PENDING') {
    return (
      <span className="inline-flex items-center rounded-full bg-amber-50 px-2 py-0.5 text-xs font-medium text-amber-700 dark:bg-amber-950/20 dark:text-amber-400">
        Pending
      </span>
    );
  }
  return (
    <span className="inline-flex items-center rounded-full bg-zinc-100 px-2 py-0.5 text-xs font-medium text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400">
      Disabled
    </span>
  );
}

export function RoleBadge({ role }: { role: RoleValue }) {
  const label = getRoleLabel(role);
  return (
    <span className="inline-flex items-center rounded-full bg-surface-elevated border border-border px-2 py-0.5 text-xs font-medium text-foreground">
      {label}
    </span>
  );
}
