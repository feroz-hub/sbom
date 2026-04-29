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

  const status: Status = useMemo(() => {
    if (isLoading) return 'unknown';
    if (isError) return 'down';
    if (!data) return 'unknown';
    if (data.status !== 'ok') return 'degraded';
    if (data.nvd_mirror?.stale) return 'degraded';
    return 'healthy';
  }, [data, isLoading, isError]);

  const meta = STATUS_META[status];
  const lastChecked = relativeTime(new Date(dataUpdatedAt).toISOString());
  const mirrorRel = relativeTime(data?.nvd_mirror?.last_success_at ?? null);

  if (compact) {
    return (
      <div
        className="flex h-8 items-center justify-center"
        title={`${meta.label}${lastChecked ? ` · checked ${lastChecked}` : ''}`}
        aria-label={`Status: ${meta.label}`}
      >
        <span
          aria-hidden
          className={cn('inline-flex h-2 w-2 rounded-full', meta.dotClass, status !== 'down' && 'pulse-dot')}
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
          {data?.nvd_mirror?.available === false
            ? 'NVD mirror unavailable'
            : mirrorRel
              ? `NVD synced ${mirrorRel}`
              : data?.nvd_mirror?.enabled === false
                ? 'NVD mirror disabled'
                : lastChecked
                  ? `Checked ${lastChecked}`
                  : 'Live polling'}
        </p>
      </div>
    </div>
  );
}
