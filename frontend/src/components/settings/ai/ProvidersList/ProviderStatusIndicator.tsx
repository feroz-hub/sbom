'use client';

import type { AiCredential } from '@/types/ai';

interface ProviderStatusIndicatorProps {
  credential: AiCredential;
}

/** Connection result is independent of credential presence and enablement. */
export function ProviderStatusIndicator({
  credential,
}: ProviderStatusIndicatorProps) {
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
  state: 'unknown' | 'untested' | 'ok' | 'failing';
  label: string;
  className: string;
  tooltip: string;
} {
  if (!c.last_test_at) {
    return {
      state: 'untested',
      label: 'Not tested',
      className: 'bg-surface-muted text-hcl-muted border border-border',
      tooltip: 'Run "Test connection" to verify this credential works.',
    };
  }
  if (c.last_test_success == null) {
    return {
      state: 'unknown',
      label: 'Unknown',
      className: 'bg-surface-muted text-hcl-muted border border-border',
      tooltip: 'No connection result was reported for the last test.',
    };
  }
  if (c.last_test_success === true) {
    return {
      state: 'ok',
      label: 'Verified',
      className:
        'bg-emerald-50 text-emerald-800 border border-emerald-200 dark:bg-emerald-950 dark:text-emerald-200 dark:border-emerald-800',
      tooltip: `Last test ${formatRelative(c.last_test_at)}`,
    };
  }
  const invalid = c.verification_status === 'INVALID_CREDENTIALS';
  return {
    state: 'failing',
    label: invalid ? 'Authentication failed' : 'Failed',
    className: invalid
      ? 'bg-red-50 text-red-800 border border-red-200 dark:bg-red-950 dark:text-red-200 dark:border-red-800'
      : 'bg-amber-50 text-amber-800 border border-amber-200 dark:bg-amber-950 dark:text-amber-200 dark:border-amber-800',
    tooltip: `Last test ${formatRelative(c.last_test_at)}. ${invalid ? 'Correct credentials and test again before enabling.' : c.verification_status === 'TEMPORARILY_UNAVAILABLE' ? 'Provider temporarily unavailable. Test again later.' : 'Connection could not be verified. Test again later.'}`,
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
