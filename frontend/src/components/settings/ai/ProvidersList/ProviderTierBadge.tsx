'use client';

import { Info } from 'lucide-react';
import type { AiProviderCatalogEntry } from '@/types/ai';

interface ProviderTierBadgeProps {
  /** "free" | "paid" — the credential's saved tier. */
  tier: string;
  /** Catalog entry — used to surface the rate-limit hint. */
  catalog?: AiProviderCatalogEntry | null;
  /** Compact display drops the info icon. */
  compact?: boolean;
}

/**
 * Phase 3 §3.5 — explicit free-tier indicator.
 *
 * Free-tier users see "free (15 req/min)" with an info-icon tooltip
 * explaining the limits. Paid users get a quieter neutral pill.
 */
export function ProviderTierBadge({ tier, catalog, compact }: ProviderTierBadgeProps) {
  const isFree = tier === 'free';
  const className = isFree
    ? 'bg-violet-50 text-violet-800 border border-violet-200'
    : 'bg-slate-50 text-slate-700 border border-slate-200';

  const rateLimit = isFree && catalog?.free_tier_rate_limit_rpm
    ? `${catalog.free_tier_rate_limit_rpm} req/min`
    : null;

  const tooltip = (() => {
    if (!isFree) return undefined;
    const parts: string[] = [];
    if (catalog?.free_tier_rate_limit_rpm) parts.push(`${catalog.free_tier_rate_limit_rpm} req/min`);
    if (catalog?.free_tier_daily_token_limit) {
      parts.push(`${catalog.free_tier_daily_token_limit.toLocaleString()} tokens/day`);
    }
    if (parts.length === 0) return 'Free tier — rate limits apply';
    return `Free tier limits: ${parts.join(', ')}. Batch processing larger scans will take longer or fail. Consider paid tier for production use.`;
  })();

  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ${className}`}
      title={tooltip}
      aria-label={isFree && rateLimit ? `Free tier (${rateLimit})` : `${tier} tier`}
    >
      {isFree ? `free (${rateLimit ?? 'limited'})` : 'paid'}
      {!compact && isFree ? <Info className="h-3 w-3" aria-hidden /> : null}
    </span>
  );
}
