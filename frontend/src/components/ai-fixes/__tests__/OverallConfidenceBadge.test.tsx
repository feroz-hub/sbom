// @vitest-environment jsdom
/**
 * OverallConfidenceBadge — every tier branch + the defensive fallback.
 *
 * The AiFixSection test only covers the "high" branch (its fixture is
 * hard-coded to high). The "low" branch is the safety-relevant one ("read
 * the caveats first"), so each tier's label/aria-label is locked here.
 */

import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import type { AiConfidenceTier } from '@/types/ai';
import { OverallConfidenceBadge } from '../AiFixSection/OverallConfidenceBadge';

describe('OverallConfidenceBadge', () => {
  it.each([
    ['high', 'High'],
    ['medium', 'Medium'],
    ['low', 'Low'],
  ] as const)('renders the %s tier with its label and aria-label', (tier, label) => {
    render(<OverallConfidenceBadge confidence={tier} />);
    const badge = screen.getByTestId('ai-overall-confidence');
    expect(badge).toHaveTextContent(/Overall AI confidence/i);
    expect(badge).toHaveTextContent(label);
    // The colored pill carries the exact, screen-reader-friendly label.
    expect(screen.getByLabelText(`Overall AI confidence: ${label}`)).toBeInTheDocument();
  });

  it('falls back to Medium for an unexpected value from the untyped JSON API', () => {
    // overall_confidence is a required FE type but arrives from an untyped
    // API; the switch default must degrade gracefully rather than render
    // an empty/undefined label.
    render(<OverallConfidenceBadge confidence={'bogus' as AiConfidenceTier} />);
    expect(screen.getByLabelText('Overall AI confidence: Medium')).toBeInTheDocument();
  });
});
