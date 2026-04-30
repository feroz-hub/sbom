// @vitest-environment jsdom
/**
 * FindingRowAdvanced — chips, attribution line, hover card, EPSS gating.
 *
 * The advanced row must render at least 5 dimensions per row without
 * needing expansion. Tests pin the visibility rules.
 */

import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { FindingRowAdvanced } from './FindingRowAdvanced';
import { renderWithCompareProviders } from '../__tests__/test-utils';
import type { FindingDiffRow } from '@/types/compare';
import { decorateArrow } from './AttributionLine';

const BASE: FindingDiffRow = {
  change_kind: 'added',
  vuln_id: 'CVE-2024-12345',
  severity_a: null,
  severity_b: 'high',
  kev_current: false,
  epss_current: null,
  epss_percentile_current: null,
  component_name: 'pyyaml',
  component_version_a: null,
  component_version_b: '6.0.1',
  component_purl: 'pkg:pypi/pyyaml@6.0.1',
  component_ecosystem: 'PyPI',
  fix_available: false,
  attribution: null,
};

function renderRow(overrides: Partial<FindingDiffRow> = {}) {
  return renderWithCompareProviders(
    <table>
      <tbody>
        <FindingRowAdvanced row={{ ...BASE, ...overrides }} onOpen={() => {}} />
      </tbody>
    </table>,
  );
}

describe('FindingRowAdvanced — chips', () => {
  it('renders KEV badge when kev_current is true', () => {
    renderRow({ kev_current: true });
    expect(screen.getByText('KEV')).toBeInTheDocument();
  });

  it('omits KEV badge when kev_current is false', () => {
    renderRow();
    expect(screen.queryByText('KEV')).not.toBeInTheDocument();
  });

  it('renders EPSS chip when percentile >= 0.5', () => {
    renderRow({ epss_percentile_current: 0.87 });
    expect(screen.getByText(/EPSS 87%/i)).toBeInTheDocument();
  });

  it('omits EPSS chip when percentile < 0.5', () => {
    renderRow({ epss_percentile_current: 0.4 });
    expect(screen.queryByText(/EPSS/i)).not.toBeInTheDocument();
  });

  it('omits EPSS chip when percentile is null', () => {
    renderRow({ epss_percentile_current: null });
    expect(screen.queryByText(/EPSS/i)).not.toBeInTheDocument();
  });

  it('renders FIX chip when fix_available is true', () => {
    renderRow({ fix_available: true });
    expect(screen.getByText('FIX')).toBeInTheDocument();
  });
});

describe('FindingRowAdvanced — attribution line', () => {
  it('renders attribution when present', () => {
    renderRow({
      attribution: 'introduced by upgrade pyyaml 5.4.0 → 6.0.1',
    });
    expect(
      screen.getByText(/introduced by upgrade pyyaml/i),
    ).toBeInTheDocument();
  });

  it('omits attribution row when attribution is null', () => {
    const { container } = renderRow();
    expect(container.querySelector('div.italic')).toBeNull();
  });
});

describe('decorateArrow', () => {
  it('detects upgrade arrow and tones it green', () => {
    const segs = decorateArrow('via upgrade pkg 1.0 → 2.0');
    const arrow = segs.find((s) => s.kind === 'arrow');
    expect(arrow).toBeDefined();
    if (arrow?.kind === 'arrow') expect(arrow.tone).toBe('up');
  });

  it('detects downgrade arrow', () => {
    const segs = decorateArrow('downgraded pkg 2.0 → 1.0');
    const arrow = segs.find((s) => s.kind === 'arrow');
    if (arrow?.kind === 'arrow') expect(arrow.tone).toBe('down');
  });

  it('returns single text segment when no arrow', () => {
    const segs = decorateArrow('via removal of pkg');
    expect(segs).toHaveLength(1);
    expect(segs[0].kind).toBe('text');
  });
});

describe('FindingRowAdvanced — interaction', () => {
  it('clicking the row fires onOpen', async () => {
    const onOpen = vi.fn();
    const user = userEvent.setup();
    renderWithCompareProviders(
      <table>
        <tbody>
          <FindingRowAdvanced row={BASE} onOpen={onOpen} />
        </tbody>
      </table>,
    );
    const row = screen.getByText('CVE-2024-12345').closest('tr')!;
    await user.click(row);
    expect(onOpen).toHaveBeenCalledTimes(1);
  });

  it('Enter key on a focused row fires onOpen', async () => {
    const onOpen = vi.fn();
    const user = userEvent.setup();
    renderWithCompareProviders(
      <table>
        <tbody>
          <FindingRowAdvanced row={BASE} onOpen={onOpen} />
        </tbody>
      </table>,
    );
    const row = screen.getByText('CVE-2024-12345').closest('tr')!;
    row.focus();
    await user.keyboard('{Enter}');
    expect(onOpen).toHaveBeenCalledTimes(1);
  });
});

describe('FindingRowAdvanced — version display', () => {
  it('resolved row shows version_a only', () => {
    renderRow({
      change_kind: 'resolved',
      severity_a: 'critical',
      severity_b: null,
      component_version_a: '2.16.0',
      component_version_b: null,
    });
    expect(screen.getByText('2.16.0')).toBeInTheDocument();
  });

  it('added row shows version_b only', () => {
    renderRow({ component_version_a: null, component_version_b: '6.0.1' });
    expect(screen.getByText('6.0.1')).toBeInTheDocument();
  });

  it('severity_changed shows the unchanged version (no arrow)', () => {
    renderRow({
      change_kind: 'severity_changed',
      severity_a: 'medium',
      severity_b: 'critical',
      component_version_a: '2.31.0',
      component_version_b: '2.31.0',
    });
    expect(screen.getByText('2.31.0')).toBeInTheDocument();
  });
});
