'use client';

import { cn } from '@/lib/utils';
import type { PostureDelta, RunRelationship } from '@/types/compare';
import {
  computeHeadline,
  inputsFromPosture,
  toneTextClass,
} from './headlineRules';

interface Props {
  posture: PostureDelta;
  relationship: RunRelationship | null;
}

/**
 * The Region 2 hero headline + sub-line.
 *
 *   - Headline is data-driven via `computeHeadline()` (pure function with
 *     exhaustive case match in `headlineRules.ts`).
 *   - Sub-line is the relationship descriptor, promoted from its v1 buried
 *     position. Italic, second line.
 *
 * `aria-live="polite"` on the headline so screen readers announce tone
 * changes (red → green) when the underlying diff updates. Reduced motion
 * compatible — no transitions on the text colour itself; only on the
 * crossfade overlay (handled at the parent if needed).
 */
export function HeroHeadline({ posture, relationship }: Props) {
  const { headline, tone } = computeHeadline(inputsFromPosture(posture));
  const sub = subLineFor(relationship);

  return (
    <div className="space-y-1">
      <h2
        aria-live="polite"
        aria-atomic="true"
        className={cn('font-semibold', toneTextClass(tone))}
        style={{
          fontSize: 'var(--hero-headline-size)',
          letterSpacing: 'var(--hero-headline-tracking)',
          lineHeight: 1.15,
        }}
      >
        {headline}
      </h2>
      {sub && (
        <p className="text-sm italic text-hcl-muted">
          {sub}
        </p>
      )}
    </div>
  );
}

function subLineFor(rel: RunRelationship | null): string | null {
  if (!rel) return null;

  if (rel.direction_warning) {
    return `⚠ ${rel.direction_warning}`;
  }

  const days = rel.days_between;
  let timeFragment = '';
  if (days != null) {
    if (days < 1 / 24) {
      timeFragment = '<1h apart';
    } else if (days < 1) {
      const hours = Math.round(days * 24);
      timeFragment = `${hours}h later`;
    } else {
      timeFragment = `${days.toFixed(days < 10 ? 1 : 0)} days later`;
    }
  }

  if (rel.same_sbom) {
    return timeFragment
      ? `Same SBOM, re-scanned ${timeFragment} — feed-only changes possible.`
      : 'Same SBOM re-scanned — feed-only changes possible.';
  }
  if (rel.same_project) {
    return timeFragment
      ? `Different SBOMs of the same project, ${timeFragment.replace(' later', ' apart')}.`
      : 'Different SBOMs of the same project.';
  }
  return 'Cross-project compare.';
}
