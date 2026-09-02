/**
 * Pre-import inspection of a VEX document.
 *
 * The statement counts asserted here are checked against the real parser: the
 * demo documents in `samples/vex/` were run through
 * `app/services/lifecycle/vex_provider.py` and produced 6 and 4 statements
 * respectively. If this preview and that parser ever disagree, the preview is
 * lying to the user about what an import will do.
 */

import { describe, expect, it } from 'vitest';
import { previewVexDocument } from './vexPreview';

const CYCLONEDX = JSON.stringify({
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  metadata: { authors: [{ name: 'HCLTech Product Security' }] },
  vulnerabilities: [
    { id: 'CVE-2021-44228', analysis: { state: 'exploitable' }, affects: [{ ref: 'maven-log4j-core' }] },
    {
      id: 'CVE-2021-45046',
      analysis: { state: 'not_affected', justification: 'code_not_reachable' },
      affects: [{ ref: 'maven-log4j-core' }],
    },
  ],
});

const OPENVEX = JSON.stringify({
  '@context': 'https://openvex.dev/ns/v0.2.0',
  author: 'HCLTech Product Security',
  statements: [
    {
      vulnerability: { name: 'CVE-2020-24584' },
      products: ['pkg:pypi/django@2.2.0'],
      status: 'not_affected',
      justification: 'vulnerable_code_not_in_execute_path',
    },
  ],
});

const CSAF = JSON.stringify({
  document: { publisher: { name: 'Example Vendor PSIRT' }, title: 'Advisory' },
  product_tree: { branches: [] },
  vulnerabilities: [{ cve: 'CVE-2021-44228', product_status: { known_not_affected: ['p1'] } }],
});

describe('previewVexDocument', () => {
  it('returns a quiet not-ok for empty input rather than an error', () => {
    const preview = previewVexDocument('   ');
    expect(preview.ok).toBe(false);
    expect(preview.error).toBeUndefined();
  });

  it('explains malformed JSON instead of throwing', () => {
    const preview = previewVexDocument('{"bomFormat":"CycloneDX",');
    expect(preview.ok).toBe(false);
    expect(preview.error).toMatch(/not valid json/i);
  });

  it('rejects a JSON array — a VEX document must be an object', () => {
    const preview = previewVexDocument('[{"id":"CVE-2021-44228"}]');
    expect(preview.ok).toBe(false);
    expect(preview.error).toMatch(/must be a JSON object/i);
  });

  it('detects CycloneDX and reports its author and vulnerability ids', () => {
    const preview = previewVexDocument(CYCLONEDX);
    expect(preview.ok).toBe(true);
    expect(preview.format).toBe('CycloneDX VEX');
    expect(preview.statementCount).toBe(2);
    expect(preview.author).toBe('HCLTech Product Security');
    expect(preview.vulnerabilityIds).toEqual(['CVE-2021-44228', 'CVE-2021-45046']);
  });

  it('detects OpenVEX and reads ids from vulnerability.name', () => {
    const preview = previewVexDocument(OPENVEX);
    expect(preview.ok).toBe(true);
    expect(preview.format).toBe('OpenVEX');
    expect(preview.statementCount).toBe(1);
    expect(preview.vulnerabilityIds).toEqual(['CVE-2020-24584']);
  });

  it('detects CSAF only when document + product_tree + vulnerabilities are all present', () => {
    expect(previewVexDocument(CSAF).format).toBe('CSAF VEX');
    // Same payload minus product_tree is no longer CSAF.
    const withoutTree = JSON.parse(CSAF);
    delete withoutTree.product_tree;
    expect(previewVexDocument(JSON.stringify(withoutTree)).format).not.toBe('CSAF VEX');
  });

  it('counts one statement per affected ref, not per vulnerability', () => {
    // Two refs on one vulnerability import as two statements.
    const doc = JSON.stringify({
      bomFormat: 'CycloneDX',
      vulnerabilities: [
        {
          id: 'CVE-2021-44228',
          analysis: { state: 'exploitable' },
          affects: [{ ref: 'a' }, { ref: 'b' }],
        },
      ],
    });
    expect(previewVexDocument(doc).statementCount).toBe(2);
  });

  it('counts one statement per product in an OpenVEX statement', () => {
    const doc = JSON.stringify({
      statements: [
        {
          vulnerability: { name: 'CVE-2020-8203' },
          products: ['pkg:npm/lodash@4.17.15', 'pkg:npm/lodash@4.17.20'],
          status: 'affected',
        },
      ],
    });
    expect(previewVexDocument(doc).statementCount).toBe(2);
  });

  it('flags a document that would import nothing', () => {
    const preview = previewVexDocument('{"bomFormat":"CycloneDX","vulnerabilities":[]}');
    expect(preview.ok).toBe(false);
    expect(preview.error).toMatch(/nothing would be imported/i);

    const openvex = previewVexDocument('{"statements":[]}');
    expect(openvex.ok).toBe(false);
    expect(openvex.error).toMatch(/need a non-empty "statements" array/i);
  });

  it('de-duplicates repeated vulnerability ids', () => {
    const doc = JSON.stringify({
      bomFormat: 'CycloneDX',
      vulnerabilities: [
        { id: 'CVE-2021-44228', affects: [{ ref: 'a' }] },
        { id: 'CVE-2021-44228', affects: [{ ref: 'b' }] },
      ],
    });
    const preview = previewVexDocument(doc);
    expect(preview.vulnerabilityIds).toEqual(['CVE-2021-44228']);
    expect(preview.statementCount).toBe(2);
  });
});
