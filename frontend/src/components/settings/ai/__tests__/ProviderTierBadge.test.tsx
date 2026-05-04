// @vitest-environment jsdom

import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ProviderTierBadge } from '../ProvidersList/ProviderTierBadge';
import {
  SAMPLE_ANTHROPIC_PAID_CATALOG,
  SAMPLE_GEMINI_FREE_CATALOG,
} from './test-utils';


describe('ProviderTierBadge', () => {
  it('renders free with rate limit when free tier', () => {
    render(<ProviderTierBadge tier="free" catalog={SAMPLE_GEMINI_FREE_CATALOG} />);
    expect(screen.getByText(/free \(15 req\/min\)/i)).toBeInTheDocument();
  });

  it('renders paid plainly when paid', () => {
    render(<ProviderTierBadge tier="paid" catalog={SAMPLE_ANTHROPIC_PAID_CATALOG} />);
    expect(screen.getByText(/paid/)).toBeInTheDocument();
    expect(screen.queryByText(/req\/min/)).not.toBeInTheDocument();
  });

  it('renders free with limited fallback when no rate-limit metadata', () => {
    render(<ProviderTierBadge tier="free" catalog={null} />);
    expect(screen.getByText(/free \(limited\)/i)).toBeInTheDocument();
  });
});
