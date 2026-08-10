/**
 * Adaptive headline rules — pure function, exhaustive case match.
 *
 * The Region 2 hero replaces the v1 "POSTURE DELTA" eyebrow with a
 * data-driven headline. Tone (red / green / amber / neutral) drives the
 * text colour; the headline string is a strict template per data state so
 * the output is testable, predictable, and free of i18n landmines.
 *
 * See docs/compare-ui-redesign.md §1.5 for the full copy table.
 *
 * NOT a scalar score. Per ADR-0008 PB-1, the page never collapses the diff
 * into a single number. The headline is a *qualitative direction*, not a
 * computed value.
 */

import type { PostureDelta } from '@/types/compare';

export type HeadlineTone = 'red' | 'green' | 'amber' | 'neutral';

export interface HeadlineResult {
  headline: string;
  tone: HeadlineTone;
}

/**
 * Subset of `PostureDelta` the headline depends on. Splitting it out makes
 * tests trivial (no need to construct the whole 20-field shape) and makes
 * the rule list readable.
 */
export interface HeadlineInputs {
  added: number;
  resolved: number;
  severityChanged: number;
  unchanged: number;
}

export function inputsFromPosture(p: PostureDelta): HeadlineInputs {
  return {
    added: p.findings_added_count,
    resolved: p.findings_resolved_count,
    severityChanged: p.findings_severity_changed_count,
    unchanged: p.findings_unchanged_count,
  };
}

const s = (n: number): string => (n === 1 ? '' : 's');

export function computeHeadline(input: HeadlineInputs): HeadlineResult {
  const { added, resolved, severityChanged, unchanged } = input;

  // 1. Both runs entirely empty.
  if (added === 0 && resolved === 0 && severityChanged === 0 && unchanged === 0) {
    return { headline: 'No vulnerabilities in either run.', tone: 'neutral' };
  }

  // 2. Identical-runs path. Theme 3 IdenticalRunsCard renders for this case
  //    instead of the regular hero, but this branch is documented here for
  //    completeness and so any caller that uses computeHeadline() directly
  //    on identical data still gets a sensible string.
  if (added === 0 && resolved === 0 && severityChanged === 0 && unchanged > 0) {
    return { headline: 'No changes detected.', tone: 'neutral' };
  }

  // 3. Pure additions — nothing resolved or reclassified.
  if (added > 0 && resolved === 0 && severityChanged === 0) {
    return {
      headline: `+${added} new finding${s(added)}. Nothing resolved.`,
      tone: 'red',
    };
  }

  // 4. Pure resolutions.
  if (added === 0 && resolved > 0 && severityChanged === 0) {
    return {
      headline: `−${resolved} finding${s(resolved)} resolved. No new exposure.`,
      tone: 'green',
    };
  }

  // 5. Pure severity reclassifications.
  if (added === 0 && resolved === 0 && severityChanged > 0) {
    return {
      headline: `${severityChanged} finding${s(severityChanged)} reclassified. No additions or removals.`,
      tone: 'amber',
    };
  }

  // 6. Mixed add+resolved. Direction comes from which side wins.
  let base: HeadlineResult;
  if (added > 0 && resolved > 0) {
    if (resolved > added) {
      base = {
        headline: `Net safer: −${resolved} resolved vs +${added} added.`,
        tone: 'green',
      };
    } else if (added > resolved) {
      base = {
        headline: `Net worse: +${added} new vs −${resolved} resolved.`,
        tone: 'red',
      };
    } else {
      base = {
        headline: `Mixed: +${added} new, −${resolved} resolved.`,
        tone: 'amber',
      };
    }
  } else if (added > 0) {
    // added > 0 with severityChanged but no resolved
    base = {
      headline: `+${added} new finding${s(added)}.`,
      tone: 'red',
    };
  } else {
    // resolved > 0 with severityChanged but no added
    base = {
      headline: `−${resolved} finding${s(resolved)} resolved.`,
      tone: 'green',
    };
  }

  // 7. Severity reclassifications — appended to the mixed/single-direction headlines.
  if (severityChanged > 0) {
    return {
      ...base,
      headline:
        base.headline +
        ` Plus ${severityChanged} severity reclassification${s(severityChanged)}.`,
    };
  }

  return base;
}

/**
 * Tailwind class selector for tone — kept here so consumers don't have to
 * branch on tone themselves. Returns light + dark variants.
 */
export function toneTextClass(tone: HeadlineTone): string {
  switch (tone) {
    case 'red':
      return 'text-red-700 dark:text-red-300';
    case 'green':
      return 'text-emerald-700 dark:text-emerald-300';
    case 'amber':
      return 'text-amber-700 dark:text-amber-300';
    case 'neutral':
      return 'text-hcl-navy';
  }
}
