// @vitest-environment jsdom
/**
 * PostureMetricTile direction logic.
 *
 * The tile must colour the delta correctly per metric direction:
 *   - "down-good" (KEV exposure, high+critical exposure): negative = green
 *   - "up-good"   (fix-available coverage):              positive = green
 *
 * Getting this wrong reverses the safety signal — a tile saying "things got
 * worse" while the underlying number actually improved would be the worst
 * possible kind of bug for a triage UI.
 */

import { describe, expect, it } from 'vitest';
import { render } from '@testing-library/react';
import { PostureTile as PostureMetricTile } from '@/components/compare/PostureHero/PostureTile';

function tone(container: HTMLElement): 'positive' | 'negative' | 'neutral' {
  const html = container.innerHTML;
  if (html.includes('text-emerald-700')) return 'positive';
  if (html.includes('text-red-700')) return 'negative';
  return 'neutral';
}

describe('PostureMetricTile — down-good (KEV / High+Critical)', () => {
  it('negative delta → green (improvement)', () => {
    const { container } = render(
      <PostureMetricTile
        label="KEV"
        valueA="2"
        valueB="1"
        delta={-1}
        direction="down-good"
      />,
    );
    expect(tone(container)).toBe('positive');
  });

  it('positive delta → red (regression)', () => {
    const { container } = render(
      <PostureMetricTile
        label="KEV"
        valueA="1"
        valueB="3"
        delta={2}
        direction="down-good"
      />,
    );
    expect(tone(container)).toBe('negative');
  });

  it('zero delta → neutral', () => {
    const { container } = render(
      <PostureMetricTile
        label="KEV"
        valueA="2"
        valueB="2"
        delta={0}
        direction="down-good"
      />,
    );
    expect(tone(container)).toBe('neutral');
  });
});

describe('PostureMetricTile — up-good (Fix-available coverage)', () => {
  it('positive delta → green (improvement)', () => {
    const { container } = render(
      <PostureMetricTile
        label="Fix-available"
        valueA="50%"
        valueB="80%"
        delta={30}
        direction="up-good"
        deltaSuffix="pp"
      />,
    );
    expect(tone(container)).toBe('positive');
  });

  it('negative delta → red (regression)', () => {
    const { container } = render(
      <PostureMetricTile
        label="Fix-available"
        valueA="80%"
        valueB="60%"
        delta={-20}
        direction="up-good"
        deltaSuffix="pp"
      />,
    );
    expect(tone(container)).toBe('negative');
  });
});

describe('PostureMetricTile — formatting', () => {
  it('renders +sign for positive deltas, suffix appended', () => {
    const { container } = render(
      <PostureMetricTile
        label="X"
        valueA="0"
        valueB="5"
        delta={5}
        direction="down-good"
        deltaSuffix="%"
      />,
    );
    expect(container.textContent).toContain('+5%');
  });

  it('floats are formatted with one decimal', () => {
    const { container } = render(
      <PostureMetricTile
        label="X"
        valueA="0"
        valueB="0.5"
        delta={0.7}
        direction="up-good"
      />,
    );
    expect(container.textContent).toContain('+0.7');
  });
});
