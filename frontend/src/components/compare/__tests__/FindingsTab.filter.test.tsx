// @vitest-environment jsdom
/**
 * FindingsTab filter and sort logic.
 *
 * The tab renders the URL-driven filter chips, runs the in-memory filter
 * over the diff rows, and feeds the sorted output to the table. We exercise
 * each chip and confirm the visible row order matches ADR-0008 §7.3 (kind
 * priority, then severity, then alphabetical by vuln id).
 */

import { describe, expect, it, vi } from 'vitest';
import { useState } from 'react';
import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { FindingsTab } from '@/components/compare/FindingsTab/FindingsTab';
import {
  SAMPLE_COMPARE_RESULT,
  renderWithCompareProviders,
} from './test-utils';
import type { FindingChangeKind } from '@/types/compare';

// Mock useCompareUrlState with a state-backed stub. Setters trigger
// re-renders so each chip click actually updates the visible rows. We
// don't exercise URL serialisation here — that's covered by
// useCompareUrlState's own tests.
vi.mock('@/hooks/useCompareUrlState', () => {
  return {
    useCompareUrlState: () => useFakeUrlState(),
  };
});

// Stub the CVE detail dialog — we don't want it fetching while these tests
// click rows to verify ordering.
vi.mock('@/components/vulnerabilities/CveDetailDialog', () => ({
  CveDetailDialog: ({ open }: { open: boolean }) =>
    open ? <div data-testid="cve-modal-stub" /> : null,
}));

// Module-singleton hook factory — single useState in module scope keeps the
// state alive across the FindingsTab's nested components inside one render.
function useFakeUrlState() {
  const [changeKinds, setChangeKinds] = useState<Set<FindingChangeKind>>(
    new Set(['added', 'resolved', 'severity_changed']),
  );
  const [severities, setSeverities] = useState<Set<string>>(
    new Set(['critical', 'high', 'medium', 'low', 'unknown']),
  );
  const [kevOnly, setKevOnly] = useState(false);
  const [fixAvailable, setFixAvailable] = useState(false);
  const [showUnchanged, setShowUnchanged] = useState(false);
  const [q, setQ] = useState('');

  return {
    runA: 1,
    runB: 2,
    tab: 'findings' as const,
    changeKinds,
    severities,
    kevOnly,
    fixAvailable,
    showUnchanged,
    q,
    setRuns: () => {},
    swap: () => {},
    setTab: () => {},
    setChangeKinds,
    toggleChangeKind: (k: FindingChangeKind) =>
      setChangeKinds((prev) => {
        const next = new Set(prev);
        if (next.has(k)) next.delete(k);
        else next.add(k);
        return next;
      }),
    setSeverities,
    toggleSeverity: (s: string) =>
      setSeverities((prev) => {
        const next = new Set(prev);
        if (next.has(s)) next.delete(s);
        else next.add(s);
        return next;
      }),
    setKevOnly,
    setFixAvailable,
    setShowUnchanged,
    setQ,
    shareUrl: () => '',
  };
}

function rowsInOrder(): string[] {
  const tbody = document.querySelector('tbody');
  if (!tbody) return [];
  const rows = Array.from(tbody.querySelectorAll('tr'));
  return rows.map((r) => {
    const code = r.querySelector('span.font-mono');
    return code?.textContent?.trim() ?? '';
  });
}

describe('FindingsTab — default filters', () => {
  it('hides unchanged by default; sorts severity_changed → added → resolved', () => {
    renderWithCompareProviders(<FindingsTab result={SAMPLE_COMPARE_RESULT} />);

    const order = rowsInOrder();
    // Severity-changed (CVE-2023-9999) is highest priority kind.
    // Then added (CVE-2024-12345).
    // Then two resolved rows, sorted by severity desc then alpha — both
    // CRITICAL so alphabetical: CVE-2021-44832 before CVE-2021-45046.
    expect(order).toEqual([
      'CVE-2023-9999',
      'CVE-2024-12345',
      'CVE-2021-44832',
      'CVE-2021-45046',
    ]);
  });
});

describe('FindingsTab — chip filters', () => {
  it('toggling Resolved chip removes those rows', async () => {
    const user = userEvent.setup();
    renderWithCompareProviders(<FindingsTab result={SAMPLE_COMPARE_RESULT} />);

    const button = screen.getByRole('button', { name: /Resolved/i });
    await user.click(button);

    const order = rowsInOrder();
    expect(order).not.toContain('CVE-2021-44832');
    expect(order).not.toContain('CVE-2021-45046');
    expect(order).toContain('CVE-2023-9999');
    expect(order).toContain('CVE-2024-12345');
  });

  it('KEV-only chip narrows to currently-KEV rows', async () => {
    const user = userEvent.setup();
    renderWithCompareProviders(<FindingsTab result={SAMPLE_COMPARE_RESULT} />);

    await user.click(screen.getByRole('button', { name: /currently in CISA KEV/i }));

    const order = rowsInOrder();
    // Only the two log4j CVEs are KEV-listed in the fixture.
    expect(new Set(order)).toEqual(
      new Set(['CVE-2021-44832', 'CVE-2021-45046']),
    );
  });

  it('Fix-available chip narrows to remediable rows', async () => {
    const user = userEvent.setup();
    renderWithCompareProviders(<FindingsTab result={SAMPLE_COMPARE_RESULT} />);

    await user.click(screen.getByRole('button', { name: /findings with a known fix/i }));

    const order = rowsInOrder();
    // CVE-2023-9999 (requests) has fix_available=false in the fixture; all
    // others have a fix.
    expect(order).not.toContain('CVE-2023-9999');
  });
});

describe('FindingsTab — free text', () => {
  it('matches vuln_id substring', async () => {
    const user = userEvent.setup();
    renderWithCompareProviders(<FindingsTab result={SAMPLE_COMPARE_RESULT} />);

    const input = screen.getByPlaceholderText(/Filter by CVE id/i);
    await user.type(input, '2024');

    const order = rowsInOrder();
    expect(order).toEqual(['CVE-2024-12345']);
  });

  it('matches component name substring', async () => {
    const user = userEvent.setup();
    renderWithCompareProviders(<FindingsTab result={SAMPLE_COMPARE_RESULT} />);

    const input = screen.getByPlaceholderText(/Filter by CVE id/i);
    await user.type(input, 'log4j');

    const order = rowsInOrder();
    expect(new Set(order)).toEqual(
      new Set(['CVE-2021-44832', 'CVE-2021-45046']),
    );
  });
});

describe('FindingsTab — show unchanged', () => {
  it('Show unchanged toggle reveals unchanged rows', async () => {
    const user = userEvent.setup();
    const withUnchanged = {
      ...SAMPLE_COMPARE_RESULT,
      findings: [
        ...SAMPLE_COMPARE_RESULT.findings,
        {
          change_kind: 'unchanged' as const,
          vuln_id: 'CVE-2025-0001',
          severity_a: 'low' as const,
          severity_b: 'low' as const,
          kev_current: false,
          epss_current: null,
          epss_percentile_current: null,
          component_name: 'cool-pkg',
          component_version_a: '1.0.0',
          component_version_b: '1.0.0',
          component_purl: null,
          component_ecosystem: null,
          fix_available: false,
          attribution: null,
        },
      ],
    };

    renderWithCompareProviders(<FindingsTab result={withUnchanged} />);
    expect(rowsInOrder()).not.toContain('CVE-2025-0001');

    await user.click(screen.getByRole('button', { name: /Show unchanged/i }));
    expect(rowsInOrder()).toContain('CVE-2025-0001');
  });
});

describe('FindingsTab — empty state', () => {
  it('shows the no-rows message when filters exclude everything', async () => {
    const user = userEvent.setup();
    renderWithCompareProviders(<FindingsTab result={SAMPLE_COMPARE_RESULT} />);

    const input = screen.getByPlaceholderText(/Filter by CVE id/i);
    await user.type(input, 'no-such-cve-anywhere');

    expect(
      screen.getByText(/No findings match the active filters/i),
    ).toBeInTheDocument();
  });
});
