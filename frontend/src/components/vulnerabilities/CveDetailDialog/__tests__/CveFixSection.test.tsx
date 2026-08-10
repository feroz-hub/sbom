// @vitest-environment jsdom
import { describe, expect, it } from 'vitest';
import userEvent from '@testing-library/user-event';
import { screen, waitFor } from '@testing-library/react';
import { CveFixSection } from '../CveFixSection';
import { FULL_DETAIL, NO_FIX_DETAIL, SCAN_DETAIL } from './fixtures';
import { installClipboardStub, renderWithProviders } from './test-utils';

describe('CveFixSection', () => {
  it('renders the grouped fix-version table on the global (non-scan) variant', () => {
    renderWithProviders(<CveFixSection detail={FULL_DETAIL} />);
    // Heading
    expect(screen.getByText('How do I fix it?')).toBeInTheDocument();
    // npm grouping label
    expect(screen.getByText('npm')).toBeInTheDocument();
    // Both fix versions surfaced
    expect(screen.getByText('1.3.1')).toBeInTheDocument();
    expect(screen.getByText('2.0.0')).toBeInTheDocument();
    // No upgrade callout — we don't have current-version context
    expect(screen.queryByText(/Upgrade/i)).not.toBeInTheDocument();
  });

  it('shows the upgrade callout and a copyable install command on the scan-aware variant', async () => {
    const { writes } = installClipboardStub();
    renderWithProviders(<CveFixSection detail={SCAN_DETAIL} />);

    // Upgrade callout text — broken across nodes, so use a partial regex match.
    expect(screen.getByText(/Upgrade/)).toBeInTheDocument();
    // The install command for npm
    const cmd = 'npm install left-pad@1.3.1';
    const copyButton = screen.getByRole('button', { name: `Copy command: ${cmd}` });
    expect(copyButton).toBeInTheDocument();

    await userEvent.click(copyButton);
    await waitFor(() => expect(writes).toEqual([cmd]));
  });

  it('shows the friendly "no fix available" message when the source list is empty', () => {
    renderWithProviders(<CveFixSection detail={NO_FIX_DETAIL} />);
    expect(
      screen.getByText(/No fix versions are available from any source yet/),
    ).toBeInTheDocument();
  });

  it('shows the "already at-or-above every fix" notice when the scan reports fixed', () => {
    renderWithProviders(
      <CveFixSection
        detail={{ ...SCAN_DETAIL, current_version_status: 'fixed', recommended_upgrade: null }}
      />,
    );
    expect(
      screen.getByText(/already at-or-above every published fix/i),
    ).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Copy command/ })).not.toBeInTheDocument();
  });
});
