// @vitest-environment jsdom
/**
 * TabsAdaptive — count badges, zero-state dimming, dot indicator priority.
 *
 * The dot indicator on the Findings tab is critical UX: when an added
 * finding is critical or high, the dot draws the eye to the actionable
 * tab before the user starts scrolling.
 */

import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import { TabsAdaptive } from './TabsAdaptive';
import {
  renderWithCompareProviders,
  SAMPLE_COMPARE_RESULT,
} from '../__tests__/test-utils';
import type { CompareResult, FindingDiffRow } from '@/types/compare';

function withFindings(
  rows: FindingDiffRow[],
): CompareResult {
  return {
    ...SAMPLE_COMPARE_RESULT,
    findings: rows,
  };
}

const FINDING: FindingDiffRow = {
  change_kind: 'added',
  vuln_id: 'CVE-2024-1',
  severity_a: null,
  severity_b: 'high',
  kev_current: false,
  epss_current: null,
  epss_percentile_current: null,
  component_name: 'pkg',
  component_version_a: null,
  component_version_b: '1.0',
  component_purl: null,
  component_ecosystem: null,
  fix_available: false,
  attribution: null,
};

describe('TabsAdaptive — counts', () => {
  it('shows non-zero counts as plain text', () => {
    renderWithCompareProviders(
      <TabsAdaptive
        current="findings"
        setTab={() => {}}
        result={SAMPLE_COMPARE_RESULT}
      />,
    );
    // SAMPLE has 1 added + 2 resolved + 1 severity = 4 non-unchanged findings
    // and 2 non-unchanged components.
    expect(screen.getByRole('tab', { name: /Findings/ })).toHaveTextContent('(4)');
    expect(screen.getByRole('tab', { name: /Components/ })).toHaveTextContent('(2)');
  });

  it('renders no count for the Posture detail tab', () => {
    renderWithCompareProviders(
      <TabsAdaptive
        current="findings"
        setTab={() => {}}
        result={SAMPLE_COMPARE_RESULT}
      />,
    );
    const delta = screen.getByRole('tab', { name: /Posture detail/ });
    expect(delta.textContent).toBe('Posture detail');
  });
});

describe('TabsAdaptive — clicking a tab fires setTab', () => {
  it('calls setTab with the canonical key', async () => {
    const setTab = vi.fn();
    const user = (await import('@testing-library/user-event')).default.setup();
    renderWithCompareProviders(
      <TabsAdaptive
        current="findings"
        setTab={setTab}
        result={SAMPLE_COMPARE_RESULT}
      />,
    );
    await user.click(screen.getByRole('tab', { name: /Components/ }));
    expect(setTab).toHaveBeenCalledWith('components');
    await user.click(screen.getByRole('tab', { name: /Posture detail/ }));
    expect(setTab).toHaveBeenCalledWith('delta');
  });
});

describe('TabsAdaptive — dot indicator', () => {
  it('renders red critical dot when an added finding is critical', () => {
    const rows: FindingDiffRow[] = [
      { ...FINDING, severity_b: 'critical' },
    ];
    renderWithCompareProviders(
      <TabsAdaptive
        current="findings"
        setTab={() => {}}
        result={withFindings(rows)}
      />,
    );
    const dot = screen.getByLabelText(/1 new critical finding/i);
    expect(dot).toBeInTheDocument();
  });

  it('renders amber high dot when no critical, but high added is present', () => {
    const rows: FindingDiffRow[] = [
      { ...FINDING, severity_b: 'high' },
      { ...FINDING, vuln_id: 'CVE-2024-2', severity_b: 'high' },
    ];
    renderWithCompareProviders(
      <TabsAdaptive
        current="findings"
        setTab={() => {}}
        result={withFindings(rows)}
      />,
    );
    const dot = screen.getByLabelText(/2 new high-severity findings/i);
    expect(dot).toBeInTheDocument();
  });

  it('omits dot when no added findings are critical or high', () => {
    const rows: FindingDiffRow[] = [
      { ...FINDING, severity_b: 'medium' },
      { ...FINDING, vuln_id: 'CVE-2024-2', severity_b: 'low' },
    ];
    renderWithCompareProviders(
      <TabsAdaptive
        current="findings"
        setTab={() => {}}
        result={withFindings(rows)}
      />,
    );
    expect(screen.queryByLabelText(/new critical/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/new high-severity/i)).not.toBeInTheDocument();
  });

  it('critical takes priority over high', () => {
    const rows: FindingDiffRow[] = [
      { ...FINDING, severity_b: 'critical' },
      { ...FINDING, vuln_id: 'CVE-2024-2', severity_b: 'high' },
    ];
    renderWithCompareProviders(
      <TabsAdaptive
        current="findings"
        setTab={() => {}}
        result={withFindings(rows)}
      />,
    );
    expect(screen.getByLabelText(/1 new critical finding/i)).toBeInTheDocument();
    expect(screen.queryByLabelText(/new high-severity/i)).not.toBeInTheDocument();
  });

  it('only counts added findings — resolved criticals do NOT trigger the dot', () => {
    const rows: FindingDiffRow[] = [
      {
        ...FINDING,
        change_kind: 'resolved',
        severity_a: 'critical',
        severity_b: null,
      },
    ];
    renderWithCompareProviders(
      <TabsAdaptive
        current="findings"
        setTab={() => {}}
        result={withFindings(rows)}
      />,
    );
    expect(screen.queryByLabelText(/new critical/i)).not.toBeInTheDocument();
  });
});
