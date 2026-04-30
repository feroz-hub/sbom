// @vitest-environment jsdom
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import { CveReferences } from '../CveReferences';
import { FULL_DETAIL, PARTIAL_DETAIL } from './fixtures';
import { renderWithProviders } from './test-utils';

describe('CveReferences', () => {
  it('renders all three "Open in" buttons with the right targets', () => {
    renderWithProviders(<CveReferences detail={FULL_DETAIL} />);
    expect(screen.getByRole('link', { name: /Open in GHSA/i })).toHaveAttribute(
      'href',
      'https://github.com/advisories/GHSA-fake-osv',
    );
    expect(screen.getByRole('link', { name: /Open in NVD/i })).toHaveAttribute(
      'href',
      'https://nvd.nist.gov/vuln/detail/CVE-2099-9001',
    );
    expect(screen.getByRole('link', { name: /Open in OSV/i })).toHaveAttribute(
      'href',
      'https://osv.dev/vulnerability/CVE-2099-9001',
    );
  });

  it('lists sources used and shows the partial-data chip when is_partial=true', () => {
    renderWithProviders(<CveReferences detail={PARTIAL_DETAIL} />);
    // Only OSV in the partial fixture.
    expect(screen.getByText(/Sources used:/i)).toBeInTheDocument();
    expect(screen.getByText('partial data')).toBeInTheDocument();
  });

  it('does NOT render the partial-data chip on full data', () => {
    renderWithProviders(<CveReferences detail={FULL_DETAIL} />);
    expect(screen.queryByText('partial data')).not.toBeInTheDocument();
  });

  it('reveals the full reference list when the user expands the disclosure', () => {
    renderWithProviders(<CveReferences detail={FULL_DETAIL} />);
    expect(screen.getByText(/All references \(3\)/)).toBeInTheDocument();
    // Patch URL is in the references list.
    expect(screen.getByText('https://example.com/patch')).toBeInTheDocument();
  });
});
