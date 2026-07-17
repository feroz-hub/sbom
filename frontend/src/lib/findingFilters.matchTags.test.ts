/**
 * Unit tests for PR-E's three new filter predicates:
 *   1. match_reason two-state (verified / not_verified / all)
 *   2. match_confidence minimum threshold
 *   3. match_strategy multi-select
 *
 * Pure-function level — no React, no jsdom. Exercises ``matchesFindingFilter``
 * with constructed ``EnrichedFinding`` rows.
 */

import { describe, expect, it } from 'vitest';

import {
  countActiveFilters,
  DEFAULT_FILTERS,
  matchesFindingFilter,
  type FindingsFilterState,
} from './findingFilters';
import type { EnrichedFinding, MatchReason, MatchStrategy } from '@/types';

function makeFinding(overrides: Partial<EnrichedFinding> = {}): EnrichedFinding {
  return {
    id: 1,
    analysis_run_id: 1,
    vuln_id: 'CVE-2024-0001',
    title: null,
    description: null,
    severity: 'HIGH',
    score: 7.0,
    vector: null,
    published_on: null,
    reference_url: null,
    cwe: null,
    cpe: null,
    component_name: 'pkg',
    component_version: '1.0.0',
    fixed_versions: null,
    attack_vector: null,
    cvss_version: null,
    aliases: null,
    source: 'NVD',
    in_kev: false,
    epss: 0,
    epss_percentile: null,
    risk_score: 0,
    cve_aliases: [],
    ...overrides,
  } as EnrichedFinding;
}

function filterWith(overrides: Partial<FindingsFilterState>): FindingsFilterState {
  return { ...DEFAULT_FILTERS, ...overrides };
}

describe('matchesFindingFilter — match_reason two-state', () => {
  it('all (default) — keeps every reason value AND null', () => {
    const f = filterWith({});
    for (const reason of [
      'matched',
      'and_node_ambiguous',
      'version_unparseable',
      null,
    ] as Array<MatchReason | null>) {
      expect(matchesFindingFilter(makeFinding({ match_reason: reason }), f)).toBe(true);
    }
  });

  it('verified — keeps only match_reason === "matched"', () => {
    const f = filterWith({ matchReasonFilter: 'verified' });
    expect(matchesFindingFilter(makeFinding({ match_reason: 'matched' }), f)).toBe(true);
    expect(
      matchesFindingFilter(makeFinding({ match_reason: 'and_node_ambiguous' }), f),
    ).toBe(false);
    // Null reason — pre-filter row — is excluded under any non-``all``.
    expect(matchesFindingFilter(makeFinding({ match_reason: null }), f)).toBe(false);
  });

  it('not_verified — keeps any conservative-keep reason, drops matched and null', () => {
    const f = filterWith({ matchReasonFilter: 'not_verified' });
    for (const reason of [
      'and_node_ambiguous',
      'version_unparseable',
      'ecosystem_unsupported',
      'no_configurations',
    ] as MatchReason[]) {
      expect(matchesFindingFilter(makeFinding({ match_reason: reason }), f)).toBe(true);
    }
    expect(matchesFindingFilter(makeFinding({ match_reason: 'matched' }), f)).toBe(false);
    expect(matchesFindingFilter(makeFinding({ match_reason: null }), f)).toBe(false);
  });
});

describe('matchesFindingFilter — match_confidence minimum threshold', () => {
  it('threshold 0 is the no-op default', () => {
    const f = filterWith({ matchConfidenceMin: 0 });
    expect(matchesFindingFilter(makeFinding({ match_confidence: 0.1 }), f)).toBe(true);
    expect(matchesFindingFilter(makeFinding({ match_confidence: null }), f)).toBe(true);
  });

  it('threshold 0.5 — keeps >= 0.5, drops < 0.5 AND null', () => {
    const f = filterWith({ matchConfidenceMin: 0.5 });
    expect(matchesFindingFilter(makeFinding({ match_confidence: 0.5 }), f)).toBe(true);
    expect(matchesFindingFilter(makeFinding({ match_confidence: 0.85 }), f)).toBe(true);
    expect(matchesFindingFilter(makeFinding({ match_confidence: 0.499 }), f)).toBe(false);
    expect(matchesFindingFilter(makeFinding({ match_confidence: null }), f)).toBe(false);
  });
});

describe('matchesFindingFilter — match_strategy multi-select', () => {
  it('empty selection is the no-op default', () => {
    const f = filterWith({ matchStrategies: [] });
    expect(matchesFindingFilter(makeFinding({ match_strategy: 'cpe_name' }), f)).toBe(true);
    expect(matchesFindingFilter(makeFinding({ match_strategy: null }), f)).toBe(true);
  });

  it('single-strategy selection narrows to that strategy', () => {
    const f = filterWith({ matchStrategies: ['cpe_name'] });
    expect(matchesFindingFilter(makeFinding({ match_strategy: 'cpe_name' }), f)).toBe(true);
    expect(matchesFindingFilter(makeFinding({ match_strategy: 'purl_direct' }), f)).toBe(
      false,
    );
    expect(matchesFindingFilter(makeFinding({ match_strategy: null }), f)).toBe(false);
  });

  it('multi-strategy is OR across selected values', () => {
    const f = filterWith({
      matchStrategies: ['purl_direct', 'ghsa_alias'] as MatchStrategy[],
    });
    expect(matchesFindingFilter(makeFinding({ match_strategy: 'purl_direct' }), f)).toBe(
      true,
    );
    expect(matchesFindingFilter(makeFinding({ match_strategy: 'ghsa_alias' }), f)).toBe(
      true,
    );
    expect(matchesFindingFilter(makeFinding({ match_strategy: 'cpe_name' }), f)).toBe(
      false,
    );
  });
});

describe('matchesFindingFilter — KEV and ransomware filters', () => {
  it('kevOnly accepts either the legacy in_kev flag or the new is_kev flag', () => {
    const f = filterWith({ kevOnly: true });
    expect(matchesFindingFilter(makeFinding({ in_kev: true }), f)).toBe(true);
    expect(matchesFindingFilter(makeFinding({ in_kev: false, is_kev: true }), f)).toBe(true);
    expect(matchesFindingFilter(makeFinding({ in_kev: false, is_kev: false }), f)).toBe(false);
  });

  it('supports canonical KEV-only and non-KEV-only status values', () => {
    const kev = makeFinding({ is_kev: true, in_kev: false });
    const nonKev = makeFinding({ is_kev: false, in_kev: false });

    expect(matchesFindingFilter(kev, filterWith({ kevStatus: 'kev' }))).toBe(true);
    expect(matchesFindingFilter(nonKev, filterWith({ kevStatus: 'kev' }))).toBe(false);
    expect(matchesFindingFilter(kev, filterWith({ kevStatus: 'non-kev' }))).toBe(false);
    expect(matchesFindingFilter(nonKev, filterWith({ kevStatus: 'non-kev' }))).toBe(true);
  });

  it('ransomwareOnly keeps findings marked as known ransomware campaign use', () => {
    const f = filterWith({ ransomwareOnly: true });
    expect(matchesFindingFilter(makeFinding({ ransomware_status: 'Known' }), f)).toBe(true);
    expect(matchesFindingFilter(makeFinding({ ransomware_status: 'known' }), f)).toBe(true);
    expect(matchesFindingFilter(makeFinding({ ransomware_status: 'Unknown' }), f)).toBe(false);
    expect(matchesFindingFilter(makeFinding({ ransomware_status: null }), f)).toBe(false);
  });

  it('supports exact known and not-known ransomware statuses across both aliases', () => {
    const primaryKnown = makeFinding({ ransomware_status: ' KNOWN ' });
    const aliasKnown = makeFinding({
      ransomware_status: null,
      known_ransomware_campaign_use: 'known',
    });
    const unknown = makeFinding({ ransomware_status: 'Unknown' });
    const notKnown = makeFinding({ ransomware_status: 'Not Known' });

    for (const finding of [primaryKnown, aliasKnown]) {
      expect(
        matchesFindingFilter(finding, filterWith({ ransomwareStatus: 'known' })),
      ).toBe(true);
      expect(
        matchesFindingFilter(finding, filterWith({ ransomwareStatus: 'not-known' })),
      ).toBe(false);
    }
    for (const finding of [unknown, notKnown, makeFinding({ ransomware_status: null })]) {
      expect(
        matchesFindingFilter(finding, filterWith({ ransomwareStatus: 'known' })),
      ).toBe(false);
      expect(
        matchesFindingFilter(finding, filterWith({ ransomwareStatus: 'not-known' })),
      ).toBe(true);
    }
  });
});

describe('matchesFindingFilter — enriched search and dimensions', () => {
  const enriched = makeFinding({
    vuln_id: 'CVE-2021-44228',
    component_name: 'log4j-core',
    component_version: '2.14.1',
    title: 'Remote Code Execution',
    vendor_project: 'Apache',
    product: 'Log4j2',
    severity: 'CRITICAL',
  });

  it.each([
    ['CVE', '  cve-2021-44228  '],
    ['package', 'LOG4J-CORE'],
    ['package version', '2.14.1'],
    ['vendor', 'apache'],
    ['product', 'log4j2'],
    ['vulnerability title', 'remote code'],
  ])('searches by %s case-insensitively', (_field, search) => {
    expect(matchesFindingFilter(enriched, filterWith({ search }))).toBe(true);
  });

  it('uses OR across search fields rather than requiring every field to match', () => {
    for (const search of ['CVE-2021', 'log4j-core', 'Apache', 'Log4j2']) {
      expect(matchesFindingFilter(enriched, filterWith({ search }))).toBe(true);
    }
    expect(matchesFindingFilter(enriched, filterWith({ search: 'Microsoft' }))).toBe(false);
  });

  it('matches severity, vendor, and product exactly and case-insensitively', () => {
    expect(
      matchesFindingFilter(
        enriched,
        filterWith({ severityFilter: 'critical', vendor: 'apache', product: 'log4j2' }),
      ),
    ).toBe(true);
    expect(matchesFindingFilter(enriched, filterWith({ severityFilter: 'high' }))).toBe(false);
    expect(matchesFindingFilter(enriched, filterWith({ vendor: 'Apach' }))).toBe(false);
    expect(matchesFindingFilter(enriched, filterWith({ product: 'Log4j' }))).toBe(false);
  });

  it('combines all selected dimensions with AND logic', () => {
    const filters = filterWith({
      search: 'log4j',
      severityFilter: 'CRITICAL',
      kevStatus: 'kev',
      ransomwareStatus: 'known',
      vendor: 'Apache',
      product: 'Log4j2',
    });
    const matching = { ...enriched, is_kev: true, ransomware_status: 'Known' };
    expect(matchesFindingFilter(matching, filters)).toBe(true);
    expect(matchesFindingFilter({ ...matching, product: 'Tomcat' }, filters)).toBe(false);
    expect(matchesFindingFilter({ ...matching, ransomware_status: 'Unknown' }, filters)).toBe(false);
  });

  it('counts search, severity, statuses, vendor, and product as active filters', () => {
    expect(countActiveFilters(filterWith({
      search: 'log4j',
      severityFilter: 'CRITICAL',
      kevStatus: 'kev',
      ransomwareStatus: 'known',
      vendor: 'Apache',
      product: 'Log4j2',
    }))).toBe(6);
  });
});

describe('matchesFindingFilter — composition', () => {
  it('three new filters AND with each other and with prior filters', () => {
    const f = filterWith({
      matchReasonFilter: 'verified',
      matchConfidenceMin: 0.6,
      matchStrategies: ['cpe_name'],
      cvssMin: 5,
    });
    // All four conditions pass → kept.
    const pass = makeFinding({
      match_reason: 'matched',
      match_confidence: 0.85,
      match_strategy: 'cpe_name',
      score: 7.0,
    });
    expect(matchesFindingFilter(pass, f)).toBe(true);

    // Any one condition failing → dropped.
    expect(
      matchesFindingFilter({ ...pass, match_reason: 'and_node_ambiguous' }, f),
    ).toBe(false);
    expect(matchesFindingFilter({ ...pass, match_confidence: 0.4 }, f)).toBe(false);
    expect(matchesFindingFilter({ ...pass, match_strategy: 'purl_direct' }, f)).toBe(false);
    expect(matchesFindingFilter({ ...pass, score: 3.0 }, f)).toBe(false);
  });
});
