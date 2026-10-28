'use client';

import { useEffect, useRef, useState, type ReactNode } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { CveDetail } from '@/types/cve';

interface Props {
  cveId: string;
  /** The CVE id span / link the card hovers over. */
  children: ReactNode;
}

/**
 * Hover preview for a CVE id. Cache-only:
 *
 *   - Reads from TanStack Query's cache. Keys we recognise:
 *       ['cve-detail', cveId]              ← global lookup
 *       ['cve-detail', scanId, cveId]      ← scan-aware lookup
 *   - If neither is cached, falls back to a plain "click for details"
 *     hint. We never trigger a fetch on hover — that would firehose the
 *     server when a user scrolls a long table.
 *
 * Reveal is delayed 200ms so casual cursor flyovers don't pop the card.
 * Hide is immediate. Reduced-motion users see the same thing without a
 * fade.
 *
 * The card is positioned absolutely above the trigger; the trigger is
 * given `position: relative` by the wrapping span.
 */
export function CveHoverCard({ cveId, children }: Props) {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
  }, []);

  const cached = readCachedDetail(qc, cveId);

  const reveal = () => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setOpen(true), 200);
  };
  const hide = () => {
    if (timer.current) clearTimeout(timer.current);
    setOpen(false);
  };

  return (
    <span
      className="relative"
      onMouseEnter={reveal}
      onMouseLeave={hide}
      onFocus={reveal}
      onBlur={hide}
    >
      {children}
      {open && (
        <span
          role="tooltip"
          className="absolute bottom-full left-0 z-30 mb-1.5 w-72 -translate-y-1 rounded-lg border border-border bg-surface p-3 text-left shadow-elev-3 motion-reduce:transition-none"
          // Pointer-events:none means hovering the card itself doesn't
          // keep it open — we don't want the user "trapping" the card.
          // The 200ms reveal delay is the only intentional friction.
          style={{ pointerEvents: 'none' }}
        >
          {cached ? (
            <>
              {cached.title && (
                <p className="line-clamp-2 text-xs font-semibold text-hcl-navy">
                  {cached.title}
                </p>
              )}
              <p className="mt-1 line-clamp-3 text-[11px] text-hcl-muted">
                {truncate(cached.summary, 160)}
              </p>
              <p className="mt-2 text-[10px] uppercase tracking-wider text-hcl-muted/80">
                Click for full advisory →
              </p>
            </>
          ) : (
            <p className="text-[11px] text-hcl-muted">
              Click {cveId} for the full advisory.
            </p>
          )}
        </span>
      )}
    </span>
  );
}

function readCachedDetail(
  qc: ReturnType<typeof useQueryClient>,
  cveId: string,
): CveDetail | null {
  // Try the most likely keys the existing CveDetailDialog populates.
  const candidates: ReadonlyArray<readonly unknown[]> = [
    ['cve-detail', cveId],
    ['cve-detail', null, cveId],
  ];
  for (const key of candidates) {
    const data = qc.getQueryData<CveDetail>(key as readonly unknown[]);
    if (data && typeof data.summary === 'string') return data;
  }
  // Fallback: the CveDetailDialog also writes some queries with a numeric
  // scan_id. We do a shallow scan of the cache for matching tail key.
  const all = qc
    .getQueryCache()
    .findAll({ queryKey: ['cve-detail'] });
  for (const q of all) {
    const k = q.queryKey;
    if (Array.isArray(k) && k[k.length - 1] === cveId) {
      const data = q.state.data as CveDetail | undefined;
      if (data && typeof data.summary === 'string') return data;
    }
  }
  return null;
}

function truncate(s: string, n: number): string {
  if (!s) return '';
  return s.length <= n ? s : s.slice(0, n - 1) + '…';
}
