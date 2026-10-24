import { Flame } from 'lucide-react';
import { cn } from '@/lib/utils';

interface KevBadgeProps {
  /** Hide entirely when false — convenience for table cells. */
  active?: boolean;
  /** Smaller, icon-only mode for dense rows. */
  compact?: boolean;
  className?: string;
}

/**
 * "Known Exploited Vulnerability" badge — shown when a finding's CVE is on
 * the CISA KEV catalog. The KEV signal is the single highest-confidence
 * exploit-likelihood indicator in public vuln data, so we surface it
 * prominently with a subtle pulsing red glow.
 */
export function KevBadge({ active = true, compact = false, className }: KevBadgeProps) {
  if (!active) return null;

  return (
    <span
      title="On CISA Known Exploited Vulnerabilities catalog — actively exploited in the wild."
      aria-label="Known exploited vulnerability"
      className={cn(
        'inline-flex shrink-0 items-center gap-1 rounded-full border font-semibold uppercase tracking-wider',
        'border-red-300 bg-red-50 text-red-700 shadow-glow-critical',
        'dark:border-red-800 dark:bg-red-950/60 dark:text-red-200',
        compact ? 'h-5 px-1.5 text-[9px]' : 'h-5 px-2 text-[10px]',
        className,
      )}
    >
      <Flame className={cn(compact ? 'h-3 w-3' : 'h-3 w-3')} aria-hidden />
      {!compact && 'KEV'}
    </span>
  );
}
