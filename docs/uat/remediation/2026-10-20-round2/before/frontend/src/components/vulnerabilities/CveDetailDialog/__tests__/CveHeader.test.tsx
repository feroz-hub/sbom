// @vitest-environment jsdom
import { describe, expect, it } from 'vitest';
import userEvent from '@testing-library/user-event';
import { screen, waitFor } from '@testing-library/react';
import { CveHeader } from '../CveHeader';
import { FULL_DETAIL, SEED } from './fixtures';
import { installClipboardStub, renderWithProviders } from './test-utils';

describe('CveHeader', () => {
  it('renders the CVE id, severity, and CVSS chips from full data', () => {
    renderWithProviders(<CveHeader seed={SEED} detail={FULL_DETAIL} isLoading={false} />);
    expect(screen.getByText('CVE-2099-9001')).toBeInTheDocument();
    expect(screen.getByText(/critical/i)).toBeInTheDocument();
    // CVSS v3 + v4 chips both visible
    expect(screen.getByText('9.8')).toBeInTheDocument();
    expect(screen.getByText('9.3')).toBeInTheDocument();
    expect(screen.getByText(FULL_DETAIL.title!)).toBeInTheDocument();
  });

  it('shows the KEV badge when listed', () => {
    renderWithProviders(<CveHeader seed={SEED} detail={FULL_DETAIL} isLoading={false} />);
    // KevBadge text is "KEV"; sibling EpssChip has its own label so we lock onto the trigger title.
    expect(screen.getByText('KEV')).toBeInTheDocument();
  });

  it('renders even when only the row seed is available (cold open)', () => {
    renderWithProviders(<CveHeader seed={SEED} detail={undefined} isLoading={true} />);
    // Header keeps painting from the seed — score, severity, KEV, EPSS — so the user sees
    // something useful in the cache-miss <16ms window before enrichment lands.
    expect(screen.getByText('CVE-2099-9001')).toBeInTheDocument();
    expect(screen.getByText('9.8')).toBeInTheDocument();
    expect(screen.getByText(/critical/i)).toBeInTheDocument();
    expect(screen.getByText('KEV')).toBeInTheDocument();
  });

  it('copies the CVE id to the clipboard on click', async () => {
    const { writes } = installClipboardStub();
    renderWithProviders(<CveHeader seed={SEED} detail={FULL_DETAIL} isLoading={false} />);
    const trigger = screen.getByRole('button', { name: /copy cve id cve-2099-9001/i });
    await userEvent.click(trigger);
    await waitFor(() => expect(writes).toEqual(['CVE-2099-9001']));
  });
});
