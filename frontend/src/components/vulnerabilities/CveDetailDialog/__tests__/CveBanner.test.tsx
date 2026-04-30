// @vitest-environment jsdom
import { describe, expect, it, vi } from 'vitest';
import userEvent from '@testing-library/user-event';
import { screen } from '@testing-library/react';
import { axe } from 'vitest-axe';
import { CveBanner } from '../CveBanner';
import {
  FULL_DETAIL,
  NOT_FOUND_DETAIL,
  PARTIAL_DETAIL,
  UNREACHABLE_DETAIL,
} from './fixtures';
import { renderWithProviders } from './test-utils';
import { SUPPORTED_VULN_FORMATS } from '@/lib/vulnIds';
import type { DialogState } from '../states';

const REPORT_HREF = 'https://example.com/report';

describe('CveBanner', () => {
  it('renders nothing for kind=loading', () => {
    const { container } = renderWithProviders(<CveBanner state={{ kind: 'loading' }} />);
    expect(container.textContent).toBe('');
  });

  it('renders nothing for kind=ok (no banner, the body speaks for itself)', () => {
    const { container } = renderWithProviders(
      <CveBanner state={{ kind: 'ok', data: FULL_DETAIL }} />,
    );
    expect(container.textContent).toBe('');
  });

  it('partial: amber banner, no Retry button (auto recovery)', () => {
    renderWithProviders(<CveBanner state={{ kind: 'partial', data: PARTIAL_DETAIL }} />);
    expect(screen.getByText('Some sources were unavailable')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /retry/i })).not.toBeInTheDocument();
  });

  it('not_found: slate banner, no Retry button', () => {
    renderWithProviders(<CveBanner state={{ kind: 'not_found', data: NOT_FOUND_DETAIL }} />);
    expect(screen.getByText('No advisory record found upstream')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /retry/i })).not.toBeInTheDocument();
  });

  it('unreachable: amber banner, Retry button calls onRetry', async () => {
    const onRetry = vi.fn();
    renderWithProviders(
      <CveBanner
        state={{ kind: 'unreachable', data: UNREACHABLE_DETAIL, canRetry: true }}
        onRetry={onRetry}
      />,
    );
    expect(screen.getByText("Couldn't reach the CVE database")).toBeInTheDocument();
    const retry = screen.getByRole('button', { name: /retry cve enrichment/i });
    await userEvent.click(retry);
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it('unrecognized: slate banner, supported formats listed, no Retry, Report-this link present', () => {
    const state: DialogState = {
      kind: 'unrecognized',
      rawId: 'FOOBAR-123',
      supported: SUPPORTED_VULN_FORMATS,
    };
    renderWithProviders(<CveBanner state={state} reportIssueHref={REPORT_HREF} />);
    expect(screen.getByText("We don't recognize this advisory format")).toBeInTheDocument();
    // Supported formats are surfaced.
    for (const fmt of SUPPORTED_VULN_FORMATS) {
      expect(screen.getByText(new RegExp(fmt.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&')))).toBeInTheDocument();
    }
    // No retry; report link present.
    expect(screen.queryByRole('button', { name: /retry/i })).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: /report this issue/i })).toHaveAttribute('href', REPORT_HREF);
  });

  it('fatal: red banner, both Retry and Report present', async () => {
    const onRetry = vi.fn();
    renderWithProviders(
      <CveBanner state={{ kind: 'fatal', message: 'boom' }} onRetry={onRetry} reportIssueHref={REPORT_HREF} />,
    );
    expect(screen.getByText('Something went wrong')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /report/i })).toHaveAttribute('href', REPORT_HREF);
  });

  it('passes vitest-axe with zero violations across every banner state', async () => {
    const states: DialogState[] = [
      { kind: 'partial', data: PARTIAL_DETAIL },
      { kind: 'not_found', data: NOT_FOUND_DETAIL },
      { kind: 'unreachable', data: UNREACHABLE_DETAIL, canRetry: true },
      {
        kind: 'unrecognized',
        rawId: 'FOOBAR-123',
        supported: SUPPORTED_VULN_FORMATS,
      },
      { kind: 'fatal', message: 'boom' },
    ];
    for (const state of states) {
      const { container, unmount } = renderWithProviders(
        <CveBanner state={state} onRetry={() => {}} reportIssueHref={REPORT_HREF} />,
      );
      const results = await axe(container);
      expect(results.violations, `axe violations on state=${state.kind}`).toEqual([]);
      unmount();
    }
  }, 20_000);
});
