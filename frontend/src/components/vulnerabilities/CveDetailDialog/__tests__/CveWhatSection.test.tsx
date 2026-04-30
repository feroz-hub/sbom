// @vitest-environment jsdom
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import { CveWhatSection } from '../CveWhatSection';
import { FULL_DETAIL, PARTIAL_DETAIL, SEED } from './fixtures';
import { renderWithProviders } from './test-utils';

describe('CveWhatSection', () => {
  it('renders the summary, dates, aliases, and CWE chips on full data', () => {
    renderWithProviders(
      <CveWhatSection seed={SEED} detail={FULL_DETAIL} scanName="vendor-app v1.2.0" />,
    );
    expect(screen.getByText(FULL_DETAIL.summary)).toBeInTheDocument();
    expect(screen.getByText(/Detected in left-pad@1.2.0/)).toBeInTheDocument();
    expect(screen.getByText(/via vendor-app v1.2.0/)).toBeInTheDocument();
    expect(screen.getByText('Published')).toBeInTheDocument();
    expect(screen.getByText('Last modified')).toBeInTheDocument();
    expect(screen.getByText('Aliases')).toBeInTheDocument();
    // CWE chips present and link out
    expect(screen.getByRole('link', { name: /CWE-79/i })).toHaveAttribute(
      'href',
      'https://cwe.mitre.org/data/definitions/79.html',
    );
    expect(screen.getByRole('link', { name: /CWE-89/i })).toBeInTheDocument();
  });

  it('falls back to a friendly empty-summary message and hides CWE block when no IDs', () => {
    renderWithProviders(
      <CveWhatSection
        seed={SEED}
        detail={{ ...PARTIAL_DETAIL, summary: '' }}
        scanName={null}
      />,
    );
    expect(screen.getByText(/No description available/i)).toBeInTheDocument();
    expect(screen.queryByText('Weakness types (CWE)')).not.toBeInTheDocument();
  });
});
