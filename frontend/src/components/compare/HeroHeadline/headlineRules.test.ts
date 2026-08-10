/**
 * Headline rules — exhaustive case coverage.
 *
 * The headline is the most-visible piece of adaptive copy on the compare
 * page; if a state slips through to the wrong tone we'll show a green
 * "safer" headline on a regression. Pin every state.
 */

import { describe, expect, it } from 'vitest';
import {
  computeHeadline,
  toneTextClass,
  type HeadlineInputs,
} from './headlineRules';

const z: HeadlineInputs = { added: 0, resolved: 0, severityChanged: 0, unchanged: 0 };

describe('computeHeadline — empty / identical runs', () => {
  it('both runs entirely empty → neutral', () => {
    expect(computeHeadline(z)).toEqual({
      headline: 'No vulnerabilities in either run.',
      tone: 'neutral',
    });
  });

  it('identical runs (no diff, has unchanged) → neutral, "no changes detected"', () => {
    expect(computeHeadline({ ...z, unchanged: 373 })).toEqual({
      headline: 'No changes detected.',
      tone: 'neutral',
    });
  });
});

describe('computeHeadline — single-direction', () => {
  it('only additions → red', () => {
    expect(computeHeadline({ ...z, added: 8 })).toEqual({
      headline: '+8 new findings. Nothing resolved.',
      tone: 'red',
    });
  });

  it('single addition → singular noun', () => {
    expect(computeHeadline({ ...z, added: 1 }).headline).toContain('1 new finding.');
  });

  it('only resolutions → green', () => {
    expect(computeHeadline({ ...z, resolved: 19 })).toEqual({
      headline: '−19 findings resolved. No new exposure.',
      tone: 'green',
    });
  });

  it('only severity reclassifications → amber', () => {
    expect(computeHeadline({ ...z, severityChanged: 3 })).toEqual({
      headline: '3 findings reclassified. No additions or removals.',
      tone: 'amber',
    });
  });
});

describe('computeHeadline — mixed', () => {
  it('resolved > added → net safer (green)', () => {
    expect(computeHeadline({ ...z, added: 8, resolved: 19 })).toEqual({
      headline: 'Net safer: −19 resolved vs +8 added.',
      tone: 'green',
    });
  });

  it('added > resolved → net worse (red)', () => {
    expect(computeHeadline({ ...z, added: 19, resolved: 8 })).toEqual({
      headline: 'Net worse: +19 new vs −8 resolved.',
      tone: 'red',
    });
  });

  it('added === resolved → mixed amber', () => {
    expect(computeHeadline({ ...z, added: 5, resolved: 5 })).toEqual({
      headline: 'Mixed: +5 new, −5 resolved.',
      tone: 'amber',
    });
  });
});

describe('computeHeadline — severity-changed appended', () => {
  it('mixed + severity_changed appends a sentence', () => {
    const r = computeHeadline({ ...z, added: 8, resolved: 19, severityChanged: 3 });
    expect(r.headline).toBe(
      'Net safer: −19 resolved vs +8 added. Plus 3 severity reclassifications.',
    );
    expect(r.tone).toBe('green');
  });

  it('only added + severity_changed', () => {
    const r = computeHeadline({ ...z, added: 4, severityChanged: 1 });
    expect(r.headline).toBe('+4 new findings. Plus 1 severity reclassification.');
    expect(r.tone).toBe('red');
  });

  it('only resolved + severity_changed', () => {
    const r = computeHeadline({ ...z, resolved: 4, severityChanged: 2 });
    expect(r.headline).toBe('−4 findings resolved. Plus 2 severity reclassifications.');
    expect(r.tone).toBe('green');
  });
});

describe('toneTextClass', () => {
  it('maps each tone to a Tailwind class with light + dark variants', () => {
    expect(toneTextClass('red')).toBe('text-red-700 dark:text-red-300');
    expect(toneTextClass('green')).toBe('text-emerald-700 dark:text-emerald-300');
    expect(toneTextClass('amber')).toBe('text-amber-700 dark:text-amber-300');
    expect(toneTextClass('neutral')).toBe('text-hcl-navy');
  });
});
