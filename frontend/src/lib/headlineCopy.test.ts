/**
 * Headline copy rules — every state, with pluralization and edge cases.
 *
 * The copy in `docs/dashboard-redesign.md` §2.2 is the source of truth.
 * If a string here drifts from that table, fix the table or the rules,
 * not the test — the test is intentionally rigid.
 */

import { describe, expect, it } from 'vitest';
import {
  computeHeadlineCopy,
  toneToHeadlineClass,
  toneToAmbientClass,
} from './headlineCopy';

describe('computeHeadlineCopy — no_data', () => {
  it('renders the onboarding copy regardless of zero counts', () => {
    expect(computeHeadlineCopy('no_data', { total_sboms: 0 })).toEqual({
      headline: 'No SBOMs uploaded yet.',
      subline: 'Upload your first SBOM to see your security posture here.',
      tone: 'neutral',
    });
  });
});

describe('computeHeadlineCopy — clean', () => {
  it('singular SBOM', () => {
    expect(computeHeadlineCopy('clean', { total_sboms: 1 })).toEqual({
      headline: 'All clear across 1 SBOM.',
      subline:
        'No critical or high-severity findings in your portfolio right now.',
      tone: 'success',
    });
  });

  it('plural SBOMs', () => {
    expect(computeHeadlineCopy('clean', { total_sboms: 12 })).toEqual({
      headline: 'All clear across 12 SBOMs.',
      subline:
        'No critical or high-severity findings in your portfolio right now.',
      tone: 'success',
    });
  });
});

describe('computeHeadlineCopy — kev_present', () => {
  it('singular KEV finding uses "needs"', () => {
    const copy = computeHeadlineCopy('kev_present', { kev_count: 1 });
    expect(copy.headline).toBe('1 actively exploited finding needs attention.');
    expect(copy.tone).toBe('danger');
    expect(copy.subline).toContain('CISA');
  });

  it('multiple KEV findings use "need"', () => {
    const copy = computeHeadlineCopy('kev_present', { kev_count: 12 });
    expect(copy.headline).toBe('12 actively exploited findings need attention.');
    expect(copy.tone).toBe('danger');
  });

  it('formats large counts with thousands separator', () => {
    const copy = computeHeadlineCopy('kev_present', { kev_count: 1234 });
    expect(copy.headline).toBe('1,234 actively exploited findings need attention.');
  });
});

describe('computeHeadlineCopy — criticals_no_kev', () => {
  it('singular critical, singular SBOM', () => {
    const copy = computeHeadlineCopy('criticals_no_kev', {
      critical: 1,
      total_sboms: 1,
    });
    expect(copy.headline).toBe('1 critical finding across 1 SBOM.');
    expect(copy.tone).toBe('warning');
    expect(copy.subline).toContain('CISA KEV');
  });

  it('plural criticals across plural SBOMs', () => {
    const copy = computeHeadlineCopy('criticals_no_kev', {
      critical: 12,
      total_sboms: 4,
    });
    expect(copy.headline).toBe('12 critical findings across 4 SBOMs.');
    expect(copy.tone).toBe('warning');
  });

  it('plural criticals on a single SBOM', () => {
    const copy = computeHeadlineCopy('criticals_no_kev', {
      critical: 7,
      total_sboms: 1,
    });
    expect(copy.headline).toBe('7 critical findings across 1 SBOM.');
  });
});

describe('computeHeadlineCopy — high_only', () => {
  it('singular high', () => {
    const copy = computeHeadlineCopy('high_only', { high: 1 });
    expect(copy.headline).toBe('1 high-severity finding to review.');
    expect(copy.tone).toBe('info');
    expect(copy.subline).toContain('manageable');
  });

  it('plural highs', () => {
    const copy = computeHeadlineCopy('high_only', { high: 7 });
    expect(copy.headline).toBe('7 high-severity findings to review.');
    expect(copy.tone).toBe('info');
  });
});

describe('computeHeadlineCopy — low_volume', () => {
  it('plural findings, all medium/low', () => {
    const copy = computeHeadlineCopy('low_volume', {
      total_findings: 1259,
    });
    expect(copy.headline).toBe('1,259 findings, none critical or high.');
    expect(copy.tone).toBe('neutral');
    expect(copy.subline).toContain('routine remediation');
  });

  it('singular finding (rare but valid)', () => {
    const copy = computeHeadlineCopy('low_volume', { total_findings: 1 });
    expect(copy.headline).toBe('1 finding, none critical or high.');
  });
});

describe('toneToHeadlineClass', () => {
  it('returns dark-mode-aware classes for every tone', () => {
    expect(toneToHeadlineClass('success')).toContain('emerald');
    expect(toneToHeadlineClass('success')).toContain('dark:');
    expect(toneToHeadlineClass('info')).toContain('sky');
    expect(toneToHeadlineClass('warning')).toContain('orange');
    expect(toneToHeadlineClass('danger')).toContain('red');
    expect(toneToHeadlineClass('neutral')).toContain('hcl-navy');
  });
});

describe('toneToAmbientClass', () => {
  it('returns a low-opacity background class for each tone', () => {
    for (const tone of ['success', 'info', 'warning', 'danger', 'neutral'] as const) {
      const cls = toneToAmbientClass(tone);
      expect(cls).toMatch(/bg-/);
      expect(cls).toMatch(/\/(20|30)/);
    }
  });
});
