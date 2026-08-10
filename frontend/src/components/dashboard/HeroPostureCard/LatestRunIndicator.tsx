'use client';

import { Clock } from 'lucide-react';
import { cn } from '@/lib/utils';

interface LatestRunIndicatorProps {
  /** ISO 8601 timestamp; null → component renders nothing. */
  isoTimestamp: string | null | undefined;
  className?: string;
}

/**
 * Small inline freshness line that sits under the hero sub-line. Replaces
 * the v1 `degraded` posture band — see `docs/dashboard-redesign.md` §2.5
 * for the rationale. Calm by default; bumps to amber after a week of
 * silence ("consider re-scanning") and stays informational rather than
 * alarmist beyond that.
 *
 * Returns null when no successful run has happened yet — the
 * `no_data` headline already says "no SBOMs uploaded" and another
 * variant of the same message would be noise.
 */
export function LatestRunIndicator({
  isoTimestamp,
  className,
}: LatestRunIndicatorProps) {
  if (!isoTimestamp) return null;
  const ts = new Date(isoTimestamp);
  if (Number.isNaN(ts.getTime())) return null;

  const diffMs = Date.now() - ts.getTime();
  const days = Math.floor(diffMs / (24 * 60 * 60 * 1000));
  const hours = Math.floor(diffMs / (60 * 60 * 1000));
  const minutes = Math.floor(diffMs / (60 * 1000));

  let phrase: string;
  if (minutes < 1) phrase = 'just now';
  else if (minutes < 60) phrase = `${minutes}m ago`;
  else if (hours < 24) phrase = `${hours}h ago`;
  else if (days === 1) phrase = '1 day ago';
  else phrase = `${days} days ago`;

  // Tone escalates calmly with age. We never show a red "stale" indicator
  // here — the hero is for security posture; mirror staleness belongs on
  // an admin surface.
  let trail = '';
  let toneClass = 'text-hcl-muted';
  if (days >= 30) {
    trail = ' — data may be stale.';
    toneClass = 'text-amber-600 dark:text-amber-300';
  } else if (days >= 7) {
    trail = ' — consider re-scanning.';
    toneClass = 'text-amber-600 dark:text-amber-300';
  }

  return (
    <p
      className={cn(
        'inline-flex items-center gap-1.5 text-[11px] font-medium',
        toneClass,
        className,
      )}
    >
      <Clock className="h-3 w-3" aria-hidden />
      Latest run · {phrase}
      {trail}
    </p>
  );
}
