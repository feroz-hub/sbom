'use client';

import type { AiCredential } from '@/types/ai';

interface ProviderStatusIndicatorProps {
  credential: AiCredential;
}

/**
 * Single source of truth for "what state is this provider in".
 *
 * Combines four signals into one badge:
 *   * disabled (toggle off)            → grey
 *   * never tested                     → amber (warns the admin to test)
 *   * tested + last_test_success=true  → green
 *   * tested + last_test_success=false → red
 *
 * Tooltip carries the last test timestamp + error so the operator can
 * spot stale state without opening the edit dialog.
 */
export function ProviderStatusIndicator({ credential }: ProviderStatusIndicatorProps) {
  const { state, label, className, tooltip } = describeStatus(credential);
  return (
    <span
      role="status"
      aria-label={`${credential.provider_name} status: ${label}`}
      title={tooltip}
      className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium ${className}`}
      data-status={state}
    >
      <span
        className="inline-block h-1.5 w-1.5 rounded-full bg-current"
        aria-hidden
      />
      {label}
    </span>
  );
}


function describeStatus(c: AiCredential): {
  state: 'disabled' | 'untested' | 'ok' | 'failing';
  label: string;
  className: string;
  tooltip: string;
} {
  if (!c.enabled) {
    return {
      state: 'disabled',
      label: 'Disabled',
      className: 'bg-slate-100 text-slate-600',
      tooltip: 'This credential is disabled and will not be used.',
    };
  }
  if (!c.last_test_at) {
    return {
      state: 'untested',
      label: 'Not tested',
      className: 'bg-amber-50 text-amber-800 border border-amber-200',
      tooltip: 'Run "Test connection" to verify this credential works.',
    };
  }
  if (c.last_test_success) {
    return {
      state: 'ok',
      label: 'OK',
      className: 'bg-emerald-50 text-emerald-800 border border-emerald-200',
      tooltip: `Last test ${formatRelative(c.last_test_at)}`,
    };
  }
  return {
    state: 'failing',
    label: 'Failing',
    className: 'bg-red-50 text-red-800 border border-red-200',
    tooltip:
      `Last test ${formatRelative(c.last_test_at)}: ${c.last_test_error ?? 'unknown error'}`,
  };
}


export function formatRelative(iso: string | null): string {
  if (!iso) return 'never';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  const seconds = Math.max((Date.now() - t) / 1000, 0);
  if (seconds < 60) return 'just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86_400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86_400)}d ago`;
}
