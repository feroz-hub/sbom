import { describe, expect, it } from 'vitest';
import { jsonPathValue, locateIssue, locateJsonPath, locateReportedLine, pathTokens, presentIssues } from './repairIssuePresentation';
import type { ValidationErrorEntry } from '@/types';
import type { RepairAnalysis } from '@/types/sbomAutoRepair';
const entry: ValidationErrorEntry = { code: 'SBOM_VAL_E028_SCHEMA_ENUM_VIOLATION', severity: 'error', stage: 'schema', path: 'packages.0.externalRefs.0.referenceCategory', message: 'Raw validator message', remediation: null, spec_reference: null };
describe('repair presentation and actual source navigation', () => {
  it('maps dotted array paths to the exact value even with repeated property names', () => {
    const source = '{\n "packages": [\n {"externalRefs":[{"referenceCategory":"PACKAGE-MANAGER"}]},\n {"externalRefs":[{"referenceCategory":"SECURITY"}]}\n ]\n}';
    const location = locateJsonPath(source, entry.path!);
    expect(location?.line).toBe(3);
    expect(source.slice(location!.start, location!.end)).toBe('"PACKAGE-MANAGER"');
    expect(locateJsonPath(source, 'packages[1].externalRefs[0].referenceCategory')?.line).toBe(4);
  });
  it('supports JSON pointers, escaped keys, nested arrays and Unicode offsets', () => {
    const source = '{"title":"😀","a/b":{"~key":[{"x":"é"}]}}';
    const location = locateJsonPath(source, '/a~1b/~0key/0/x');
    expect(source.slice(location!.start, location!.end)).toBe('"é"');
    expect(pathTokens('/a~1b/~0key/0/x')).toEqual(['a/b', '~key', '0', 'x']);
  });
  it('never invents source offsets for missing paths, XPath or malformed JSON', () => {
    expect(locateJsonPath('{"x":1}', 'absent')).toBeNull();
    expect(locateJsonPath('not JSON', 'x')).toBeNull();
    expect(locateIssue('{"x":1}', { ...entry, path: null, xpath: '//package/name' })).toBeNull();
    expect(locateReportedLine('a\nb', 9)).toBeNull();
  });
  it('uses only a reported, in-range line when parsing cannot locate an issue', () => {
    const location = locateIssue('invalid\ncontent', { ...entry, line: 2 });
    expect(location?.line).toBe(2);
    expect('invalid\ncontent'.slice(location!.start, location!.end)).toBe('content');
  });
  it('keeps original messages, uses deterministic guidance and does not confuse AI eligibility with safe repair', () => {
    const issue = presentIssues([{ ...entry, can_ai_fix: true }])[0];
    expect(issue.title).toBe('Invalid reference category');
    expect(issue.entry.message).toBe('Raw validator message');
    expect(issue.classification).toBeUndefined();
    const analysis = { enabled: true, issues: [{ code: entry.code, path: 'packages[0].externalRefs[0].referenceCategory', classification: 'MANUAL_ONLY' }] } as RepairAnalysis;
    expect(presentIssues([entry], analysis)[0].classification).toBe('MANUAL_ONLY');
    expect(jsonPathValue({ packages: [{ externalRefs: [{ referenceCategory: 'PACKAGE-MANAGER' }] }] }, entry.path!)).toEqual({ found: true, value: 'PACKAGE-MANAGER' });
  });
  it('keeps selected issue keys stable when another issue disappears', () => {
    const first = { ...entry, path: 'packages[1].name' };
    expect(presentIssues([first, entry])[1].key).toBe(presentIssues([entry])[0].key);
  });
});

it('presents orphan components as informational without changing the validator payload', () => {
  const original = { ...entry, code: 'SBOM_VAL_I075_ORPHAN_COMPONENT', severity: 'info' as const, path: 'components[3]', message: 'Original orphan payload' };
  const issue = presentIssues([original])[0];
  expect(issue.title).toBe('Orphan component');
  expect(issue.code).toBe('I075');
  expect(issue.entry).toBe(original);
  expect(issue.explanation).toContain('dependency graph');
});
