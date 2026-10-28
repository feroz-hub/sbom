/**
 * Tests for the scope-aware AI fix helpers.
 *
 * These shape the CTA card label and the backend POST body. They are
 * deliberately rigid — the copy in the source-of-truth tables (Phase 4
 * §3.2 of the prompt) drives this contract; if a string drifts here,
 * fix the table or the helper, not the test.
 */

import { describe, expect, it } from 'vitest';
import { buildScope, describeScope, scopeCacheKey } from './aiFixScope';
import { DEFAULT_FILTERS, type FindingsFilterState } from './findingFilters';

function withFilter(overrides: Partial<FindingsFilterState>): FindingsFilterState {
  return { ...DEFAULT_FILTERS, ...overrides };
}

describe('describeScope', () => {
  it('returns "all findings" when no filters and no selection', () => {
    expect(describeScope({ filter: DEFAULT_FILTERS })).toBe('all findings');
  });

  it('describes selection by count', () => {
    expect(
      describeScope({ filter: DEFAULT_FILTERS, selectedIds: [1, 2, 3, 4, 5] }),
    ).toBe('5 selected findings');
  });

  it('singularises selection of one', () => {
    expect(
      describeScope({ filter: DEFAULT_FILTERS, selectedIds: [42] }),
    ).toBe('1 selected finding');
  });

  it('describes a single severity filter', () => {
    expect(
      describeScope({ filter: withFilter({ severityFilter: 'CRITICAL' }) }),
    ).toBe('Critical findings');
  });

  it('describes the KEV filter alone', () => {
    expect(describeScope({ filter: withFilter({ kevOnly: true }) })).toBe(
      'KEV findings',
    );
  });

  it('composes severity and KEV without "and"', () => {
    // "critical KEV findings" reads better than "critical and KEV
    // findings" — KEV is a noun-modifier on the severity, not a peer.
    expect(
      describeScope({
        filter: withFilter({ severityFilter: 'CRITICAL', kevOnly: true }),
      }),
    ).toBe('Critical KEV findings');
  });

  it('appends "with fixes available" when hasFixOnly is set', () => {
    expect(
      describeScope({
        filter: withFilter({ severityFilter: 'HIGH', hasFixOnly: true }),
      }),
    ).toBe('High findings with fixes available');
  });

  it('appends a search query as a trailing qualifier', () => {
    expect(
      describeScope({ filter: withFilter({ search: 'log4j' }) }),
    ).toBe("Findings matching 'log4j'");
  });

  it('combines severity + search qualifier', () => {
    expect(
      describeScope({
        filter: withFilter({ severityFilter: 'MEDIUM', search: 'log4j' }),
      }),
    ).toBe("Medium findings matching 'log4j'");
  });

  it('selection takes precedence over filters', () => {
    expect(
      describeScope({
        filter: withFilter({ severityFilter: 'CRITICAL', kevOnly: true }),
        selectedIds: [1, 2],
      }),
    ).toBe('2 selected findings');
  });
});

describe('buildScope', () => {
  it('returns null when nothing is filtered or selected', () => {
    expect(buildScope({ filter: DEFAULT_FILTERS })).toBeNull();
  });

  it('returns finding_ids + label when selection is non-empty', () => {
    const scope = buildScope({
      filter: DEFAULT_FILTERS,
      selectedIds: [3, 1, 2],
    });
    expect(scope).toEqual({
      finding_ids: [1, 2, 3],
      label: 'Selected (3)',
    });
  });

  it('emits severities array for severityFilter', () => {
    const scope = buildScope({
      filter: withFilter({ severityFilter: 'CRITICAL' }),
    });
    expect(scope).toMatchObject({ severities: ['CRITICAL'], label: 'Critical findings' });
  });

  it('combines kev_only + fix_available_only + severities + search_query', () => {
    const scope = buildScope({
      filter: withFilter({
        severityFilter: 'HIGH',
        kevOnly: true,
        hasFixOnly: true,
        search: '  log4j  ',
      }),
    });
    expect(scope).toMatchObject({
      severities: ['HIGH'],
      kev_only: true,
      fix_available_only: true,
      search_query: 'log4j',
    });
    expect(scope!.label).toMatch(/High KEV findings/);
  });

  it('selection beats severity filter', () => {
    const scope = buildScope({
      filter: withFilter({ severityFilter: 'CRITICAL', kevOnly: true }),
      selectedIds: [10, 20],
    });
    // Filter dimensions are dropped when finding_ids is non-empty.
    expect(scope).toEqual({
      finding_ids: [10, 20],
      label: 'Selected (2)',
    });
    expect(scope?.severities).toBeUndefined();
    expect(scope?.kev_only).toBeUndefined();
  });
});

describe('scopeCacheKey', () => {
  it('returns a stable string for "all findings"', () => {
    expect(scopeCacheKey(null)).toBe('all');
  });

  it('hashes equivalent scopes to the same string regardless of order', () => {
    const a = buildScope({
      filter: withFilter({ severityFilter: 'CRITICAL', kevOnly: true }),
    });
    const b = buildScope({
      filter: withFilter({ kevOnly: true, severityFilter: 'CRITICAL' }),
    });
    expect(scopeCacheKey(a)).toBe(scopeCacheKey(b));
  });

  it('hashes selection by sorted finding_ids', () => {
    const a = scopeCacheKey({ finding_ids: [3, 1, 2] });
    const b = scopeCacheKey({ finding_ids: [1, 2, 3] });
    expect(a).toBe(b);
  });

  it('strips falsy / empty fields from the hash payload', () => {
    const sparse = scopeCacheKey({
      severities: ['CRITICAL'],
      kev_only: false,
      search_query: '',
      label: 'Critical findings',
    });
    expect(sparse).not.toContain('kev_only');
    expect(sparse).not.toContain('search_query');
    expect(sparse).toContain('CRITICAL');
  });
});
