'use client';

import { cn } from '@/lib/utils';

interface Props {
  /** Raw attribution text from the diff payload (already pre-formatted). */
  text: string | null;
}

/**
 * Italic second line beneath the row's primary content. Highlights the
 * version-arrow ("1.2.3 → 1.4.0") with a tone matching the upgrade
 * direction:
 *
 *   - alphabetically-greater on the right → green (most upgrades)
 *   - alphabetically-greater on the left  → red (downgrades)
 *
 * Returns null when text is null/empty so the parent can keep the row
 * single-line.
 */
export function AttributionLine({ text }: Props) {
  if (!text) return null;
  const segments = decorateArrow(text);

  return (
    <div className="text-[11px] italic text-hcl-muted">
      <span className="mr-1" aria-hidden>
        ↳
      </span>
      {segments.map((seg, i) =>
        seg.kind === 'arrow' ? (
          <span
            key={i}
            className={cn(
              'mx-0.5 not-italic font-bold',
              seg.tone === 'up' && 'text-emerald-600 dark:text-emerald-400',
              seg.tone === 'down' && 'text-red-600 dark:text-red-400',
            )}
          >
            →
          </span>
        ) : (
          <span key={i}>{seg.text}</span>
        ),
      )}
    </div>
  );
}

type Segment =
  | { kind: 'text'; text: string }
  | { kind: 'arrow'; tone: 'up' | 'down' };

/**
 * Splits an attribution string at the first " → " and decides arrow tone.
 * If no arrow is present, returns the raw text as a single segment.
 *
 * Heuristic for tone: take the version tokens immediately to the left and
 * right of the arrow (slash-stripped), compare lexicographically. This is
 * inexact (semver upgrades like 1.10 < 1.9 lexicographically) but fine for
 * an italic visual hint — the row's change_kind chip is the actual source
 * of truth for "up" vs "down".
 */
export function decorateArrow(text: string): Segment[] {
  const idx = text.indexOf(' → ');
  if (idx === -1) {
    return [{ kind: 'text', text }];
  }
  const before = text.slice(0, idx);
  const after = text.slice(idx + 3);

  // Pluck the last whitespace-separated token before the arrow and the
  // first one after. These are the candidate version strings.
  const beforeToken = before.split(/\s+/).pop() ?? '';
  const afterToken = after.split(/\s+/)[0] ?? '';
  const tone: 'up' | 'down' = afterToken > beforeToken ? 'up' : 'down';

  return [
    { kind: 'text', text: before + ' ' },
    { kind: 'arrow', tone },
    { kind: 'text', text: ' ' + after },
  ];
}
