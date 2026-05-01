'use client';

import { useQuery } from '@tanstack/react-query';
import { Activity, AlertTriangle, WifiOff } from 'lucide-react';
import { useMemo } from 'react';
import { getHealth } from '@/lib/api';
import { cn } from '@/lib/utils';

interface SidebarStatusProps {
  /** Compact mode for the collapsed sidebar — icon only. */
  compact?: boolean;
}

type Status = 'healthy' | 'degraded' | 'down' | 'unknown';

const STATUS_META: Record<
  Status,
  { dotClass: string; label: string; tone: string; Icon: typeof Activity }
> = {
  healthy: {
    dotClass: 'bg-emerald-400 text-emerald-400',
    label: 'API healthy',
    tone: 'text-emerald-300',
    Icon: Activity,
  },
  degraded: {
    dotClass: 'bg-amber-400 text-amber-400',
    label: 'Degraded',
    tone: 'text-amber-300',
    Icon: AlertTriangle,
  },
  down: {
    dotClass: 'bg-red-500 text-red-500',
    label: 'API unreachable',
    tone: 'text-red-300',
    Icon: WifiOff,
  },
  unknown: {
    dotClass: 'bg-slate-500 text-slate-400',
    label: 'Checking…',
    tone: 'text-slate-400',
    Icon: Activity,
  },
};

function relativeTime(iso: string | null | undefined): string | null {
  if (!iso) return null;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return null;
  const diff = Date.now() - date.getTime();
  if (diff < 30_000) return 'just now';
  const m = Math.floor(diff / 60_000);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d < 7) return `${d}d ago`;
  return null;
}

export function SidebarStatus({ compact = false }: SidebarStatusProps) {
  const { data, isLoading, isError, dataUpdatedAt } = useQuery({
    queryKey: ['health-poll'],
    queryFn: ({ signal }) => getHealth(signal),
    // Poll every 30 seconds. The endpoint is cheap and uncached.
    refetchInterval: 30_000,
    // Keep retrying transparently — a one-off failure shouldn't paint "down".
    retry: 1,
    staleTime: 5_000,
  });

  // v2 (redesign §7.1): user-facing status reflects API connectivity *only*.
  // The NVD mirror is an admin-controlled feed and its enabled/stale state has
  // no bearing on whether the user's analysis runs are accurate — they hit
  // public NVD regardless. Surfacing mirror state here trained the user to
  // treat "Degraded" as background noise. Mirror visibility lives on the
  // future /admin/health surface (out of scope for this redesign).
  const status: Status = useMemo(() => {
    if (isLoading) return 'unknown';
    if (isError) return 'down';
    if (!data) return 'unknown';
    if (data.status !== 'ok') return 'down';
    return 'healthy';
  }, [data, isLoading, isError]);

  const meta = STATUS_META[status];
  const lastChecked = relativeTime(new Date(dataUpdatedAt).toISOString());

  if (compact) {
    // Single neutral dot — never amber. We never want the collapsed sidebar
    // to escalate visual tone for an operator concern.
    return (
      <div
        className="flex h-8 items-center justify-center"
        title={`${meta.label}${lastChecked ? ` · checked ${lastChecked}` : ''}`}
        aria-label={`Status: ${meta.label}`}
      >
        <span
          aria-hidden
          className={cn(
            'inline-flex h-2 w-2 rounded-full',
            meta.dotClass,
            status !== 'down' && 'pulse-dot',
          )}
        />
      </div>
    );
  }

  return (
    <div
      role="status"
      aria-live="polite"
      className={cn(
        'flex items-center gap-2 rounded-lg border border-white/5 bg-white/5 px-3 py-2',
        'text-[11px] text-slate-300 transition-colors',
      )}
    >
      <span
        aria-hidden
        className={cn(
          'relative inline-flex h-2 w-2 shrink-0 rounded-full',
          meta.dotClass,
          status !== 'down' && 'pulse-dot',
        )}
      />
      <div className="min-w-0 flex-1">
        <p className={cn('truncate font-semibold', meta.tone)}>{meta.label}</p>
        <p className="truncate text-[10px] text-slate-500 font-metric tabular-nums">
          {lastChecked ? `Checked ${lastChecked}` : 'Live polling'}
        </p>
      </div>
    </div>
  );
}
