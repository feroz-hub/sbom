import { describe, expect, it } from 'vitest';
import { pluralize } from './pluralize';

describe('pluralize', () => {
  it('uses singular for 1', () => {
    expect(pluralize(1, 'SBOM', 'SBOMs')).toBe('1 SBOM');
    expect(pluralize(1, 'project', 'projects')).toBe('1 project');
  });

  it('uses plural for 0', () => {
    // English: 0 takes the "other" rule, not "one".
    expect(pluralize(0, 'SBOM', 'SBOMs')).toBe('0 SBOMs');
    expect(pluralize(0, 'project', 'projects')).toBe('0 projects');
  });

  it('uses plural for >1', () => {
    expect(pluralize(2, 'SBOM', 'SBOMs')).toBe('2 SBOMs');
    expect(pluralize(1865, 'finding', 'findings')).toBe('1,865 findings');
  });

  it('formats large numbers with thousands separators (en locale)', () => {
    expect(pluralize(2984, 'finding', 'findings')).toBe('2,984 findings');
  });

  it('regression — fixes the audit-flagged "1 SBOMs in 1 projects" bug', () => {
    // Before the fix, the hero subtext rendered "1 SBOMs in 1 projects".
    // After the fix, both must read singular.
    const sboms = pluralize(1, 'SBOM', 'SBOMs');
    const projects = pluralize(1, 'project', 'projects');
    expect(`${sboms} in ${projects}`).toBe('1 SBOM in 1 project');
  });
});
