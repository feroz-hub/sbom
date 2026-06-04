'use client';

import Link from 'next/link';
import { ArrowDownRight, ArrowUpRight, Clock3, Sparkles } from 'lucide-react';
import { Surface } from '@/components/ui/Surface';
import { cn } from '@/lib/utils';
import type { DashboardPosture } from '@/types';

interface WhatsNewStripProps {
  posture: DashboardPosture | undefined;
}

/**
 * "What's changed" strip — the delta that drives action more than any static
 * total. Reads the canonical `net_7day` envelope (falling back to the flat
 * aliases for the back-compat window) and is honest about the first period:
 * when there's no prior window to compare against it renders "first scan this
 * week" instead of a misleading "+N / −0" (Bug 5 lock, carried over from the
 * retired HeroMetricRow).
 *
 * Phase 1 links to the runs hub — one click to where the new findings live.
 * Phase 2 upgrades this to a true "new since last scan" findings drill-down
 * once that aggregate exists.
 */
export function WhatsNewStrip({ posture }: WhatsNewStripProps) {
  if (!posture) return null;

  const added = posture.net_7day?.added ?? posture.net_7day_added ?? 0;
  const resolved = posture.net_7day?.resolved ?? posture.net_7day_resolved ?? 0;
  const windowDays = posture.net_7day?.window_days ?? 7;
  const isFirstPeriod = posture.net_7day?.is_first_period ?? false;
  const net = added - resolved;

  return (
    <Surface variant="elevated" className="px-4 py-3">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <span className="inline-flex items-center gap-2 text-sm font-semibold text-hcl-navy">
          <Sparkles className="h-4 w-4 text-hcl-blue" aria-hidden />
          What&apos;s changed
        </span>

        {isFirstPeriod ? (
          <span className="inline-flex items-center gap-1.5 text-sm text-hcl-muted">
            <Clock3 className="h-3.5 w-3.5" aria-hidden />
            First scan this week — comparison available next week.
          </span>
        ) : (
          <span className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
            <span
              className={cn(
                'inline-flex items-center gap-1 font-medium',
                added > 0 ? 'text-red-700 dark:text-red-300' : 'text-hcl-muted',
              )}
            >
              <ArrowUpRight className="h-3.5 w-3.5" aria-hidden />
              <strong className="font-metric tabular-nums">{added.toLocaleString()}</strong> new
            </span>
            <span
              className={cn(
                'inline-flex items-center gap-1 font-medium',
                resolved > 0 ? 'text-emerald-700 dark:text-emerald-300' : 'text-hcl-muted',
              )}
            >
              <ArrowDownRight className="h-3.5 w-3.5" aria-hidden />
              <strong className="font-metric tabular-nums">{resolved.toLocaleString()}</strong> resolved
            </span>
            <span className="text-xs text-hcl-muted">
              distinct vulnerabilities · last {windowDays} days
              {net !== 0 && (
                <>
                  {' '}
                  ·{' '}
                  <span className={net > 0 ? 'text-red-600 dark:text-red-300' : 'text-emerald-600 dark:text-emerald-300'}>
                    net {net > 0 ? '+' : '−'}
                    {Math.abs(net).toLocaleString()}
                  </span>
                </>
              )}
            </span>
          </span>
        )}

        <Link
          href="/analysis?tab=runs"
          className="ml-auto inline-flex items-center gap-1 text-xs font-medium text-primary transition-colors hover:text-hcl-dark focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/40"
        >
          View recent runs <ArrowUpRight className="h-3 w-3" aria-hidden />
        </Link>
      </div>
    </Surface>
  );
}
