/** Presentation and source navigation only. Validator messages and repairs stay untouched. */
import type { ValidationErrorEntry } from '@/types';
import type { RepairAnalysis } from '@/types/sbomAutoRepair';

export interface SourceLocation { start: number; end: number; line: number; }
export type RepairClassification = RepairAnalysis['issues'][number]['classification'];
export interface RepairIssue {
  key: string; entry: ValidationErrorEntry; code: string; title: string;
  location: string; explanation: string; guidance: string | null; classification?: RepairClassification;
}
const descriptions: Record<string, [string, string, string]> = {
  I075: ['Orphan component', 'This component exists in the SBOM but is not connected to the dependency graph.', 'Review whether this component should be connected to the declared dependency graph.'],
  E020: ['Invalid JSON', 'The document cannot be parsed as JSON.', 'Correct the JSON syntax at the reported location.'],
  E021: ['Invalid XML', 'The document cannot be parsed as XML.', 'Correct the XML syntax at the reported location.'],
  E025: ['Invalid document structure', 'This part of the document does not match its SBOM schema.', 'Review the expected structure in the validator details.'],
  E026: ['Required field missing', 'A field required by this SBOM schema is missing.', 'Supply the required field using the document specification.'],
  E027: ['Incorrect value type', 'The value has a type that this field does not support.', 'Check the required type before editing this value.'],
  E028: ['Invalid enum value', 'The value is not supported by this SBOM field.', 'Choose a supported value from the validator details.'],
  E029: ['Invalid field format', 'The value does not match the required field format.', 'Check the format required by this SBOM specification.'],
  E040: ['Invalid SPDX identifier', 'This SPDX identifier is malformed.', 'Check the identifier format and its references before changing it.'],
  E043: ['Invalid license expression', 'The license expression could not be validated.', 'Use a valid SPDX license expression for this field.'],
  E044: ['Incorrect checksum length', 'The checksum length does not match its declared algorithm.', 'Verify the checksum and its algorithm against the source artifact.'],
  E048: ['Duplicate SPDX identifier', 'An SPDX identifier is repeated in this document.', 'Review both declarations and their references before changing an identifier.'],
  E051: ['Duplicate component reference', 'A bom-ref identifier is repeated in this document.', 'Review the identifiers and their dependency references before changing them.'],
  E052: ['Invalid package URL', 'This package URL could not be parsed as a valid PURL.', 'Replace it with a valid package URL for the same package.'],
  E053: ['Invalid CPE identifier', 'This CPE identifier could not be validated.', 'Verify the CPE format and package identity.'],
  E070: ['Broken dependency reference', 'A dependency refers to a component that is missing from the document.', 'Check the reference and declared component identifiers before changing it.'],
  E071: ['Self-referencing dependency', 'A dependency refers to itself.', 'Review the intended dependency relationship.'],
  E072: ['Broken relationship reference', 'A relationship points to an element missing from this document.', 'Check the relationship and the declared element identifiers.'],
};
export function issuePath(entry: ValidationErrorEntry) {
  return entry.json_pointer || entry.path || entry.xpath || (entry.line ? `Line ${entry.line}${entry.column ? `, column ${entry.column}` : ''}` : 'Document');
}
export function pathTokens(path: string): string[] | null {
  if (path.startsWith('#/')) path = path.slice(1);
  if (path.startsWith('/')) return path.slice(1).split('/').map(key => key.replaceAll('~1', '/').replaceAll('~0', '~'));
  if (path === '$' || path === '') return [];
  if (path.startsWith('Line ') || path.startsWith('Document') || path.startsWith('//')) return null;
  // Validator dotted paths and array indexes; arbitrary XPath is not interpreted as JSON.
  if (/[/]/.test(path)) return null;
  return path.replace(/^\$\.?/, '').replace(/\[(\d+)\]/g, '.$1').split('.').filter(Boolean);
}
export function normalizedIssuePath(path: string) { return JSON.stringify(pathTokens(path) ?? path); }
export function presentIssues(entries: ValidationErrorEntry[], analysis?: RepairAnalysis): RepairIssue[] {
  const occurrences = new Map<string, number>();
  return entries.map(entry => {
    const code = entry.code.match(/(?:^|_)([EWI]\d{3})(?:_|$)/)?.[1] ?? entry.code;
    const location = issuePath(entry);
    const known = descriptions[code];
    const base = `${entry.code}:${normalizedIssuePath(location)}:${entry.severity}`;
    const occurrence = occurrences.get(base) ?? 0;
    occurrences.set(base, occurrence + 1);
    const classification = analysis?.enabled ? analysis.issues.find(issue => issue.code === entry.code && normalizedIssuePath(issue.path) === normalizedIssuePath(location))?.classification : undefined;
    return { key: `${base}:${occurrence}`, entry, code, location, classification,
      title: code === 'E028' && location.endsWith('referenceCategory') ? 'Invalid reference category' : known?.[0] ?? (entry.code.replace(/^SBOM_VAL_[EWI]\d{3}_?/, '').toLowerCase().replaceAll('_', ' ').replace(/^./, letter => letter.toUpperCase()) || 'Document finding'),
      explanation: known?.[1] ?? 'Review this reported finding at the indicated location. The original validator message is available in Technical details.',
      guidance: entry.remediation || known?.[2] || null };
  });
}

/** Match a JSON path to actual character offsets without formatting or modifying the draft. */
export function locateJsonPath(source: string, path: string): SourceLocation | null {
  const tokens = pathTokens(path);
  if (!tokens) return null;
  try { JSON.parse(source); } catch { return null; }
  let position = 0;
  let result: SourceLocation | null = null;
  const skip = () => { while (/\s/.test(source[position] ?? '') && position < source.length) position++; };
  const string = () => {
    const start = position++;
    while (position < source.length) {
      if (source[position] === '\\') { position += 2; continue; }
      if (source[position++] === '"') break;
    }
    return JSON.parse(source.slice(start, position)) as string;
  };
  const value = (current: string[]) => {
    skip();
    const start = position;
    if (source[position] === '{') {
      position++; skip();
      while (source[position] !== '}') {
        const key = string(); skip(); position++; value([...current, key]); skip();
        if (source[position] !== ',') break;
        position++; skip();
      }
      position++;
    } else if (source[position] === '[') {
      position++; skip(); let index = 0;
      while (source[position] !== ']') {
        value([...current, String(index++)]); skip();
        if (source[position] !== ',') break;
        position++; skip();
      }
      position++;
    } else if (source[position] === '"') string();
    else while (position < source.length && !/[\s,}\]]/.test(source[position])) position++;
    if (current.length === tokens.length && current.every((part, i) => part === tokens[i])) {
      // Objects/arrays are highlighted at their opening delimiter, not as a whole file selection.
      const end = /[\[{]/.test(source[start]) ? start + 1 : position;
      result = { start, end, line: source.slice(0, start).split('\n').length };
    }
  };
  try { value([]); return result; } catch { return null; }
}
export function locateReportedLine(source: string, line?: number | null, column?: number | null): SourceLocation | null {
  if (!line || line < 1) return null;
  const lines = source.split('\n');
  if (line > lines.length) return null;
  const start = lines.slice(0, line - 1).reduce((size, text) => size + text.length + 1, 0) + Math.min(Math.max((column ?? 1) - 1, 0), lines[line - 1].length);
  return { start, end: start + Math.min(Math.max(1, lines[line - 1].length - Math.max((column ?? 1) - 1, 0)), source.length - start), line };
}
export function locateIssue(source: string, entry: ValidationErrorEntry) {
  const path = entry.json_pointer || entry.path;
  return (path ? locateJsonPath(source, path) : null) || locateReportedLine(source, entry.line, entry.column);
}

export function jsonPathValue(document: unknown, path: string): { found: boolean; value?: unknown } {
  const tokens = pathTokens(path);
  if (!tokens || document === undefined) return { found: false };
  let value: unknown = document;
  for (const key of tokens) {
    if (value === null || typeof value !== 'object' || !Object.prototype.hasOwnProperty.call(value, key)) return { found: false };
    value = (value as Record<string, unknown>)[key];
  }
  return { found: true, value };
}
