/**
 * Client-side inspection of a VEX document before it is imported.
 *
 * Purely advisory: the server re-parses and re-validates everything
 * (`app/services/lifecycle/vex_provider.py`). The point is to answer "is this
 * the file I meant, and will it do roughly what I expect" *before* a request
 * that writes statements — pasting a wrong or truncated document and finding
 * out from an error toast is the workflow this replaces.
 *
 * Format detection mirrors `_detect_format` / `_is_csaf_document` at
 * app/services/lifecycle/vex_provider.py:751 so the label shown here is the
 * label the server will act on.
 */

export type VexDocumentFormat = 'CycloneDX VEX' | 'OpenVEX' | 'CSAF VEX' | 'VEX JSON';

export interface VexDocumentPreview {
  /** False when the text is empty, not JSON, or not a JSON object. */
  ok: boolean;
  /** Human-readable reason the document cannot be previewed. */
  error?: string;
  format?: VexDocumentFormat;
  /** Statements the server is expected to read out of the document. */
  statementCount?: number;
  /** Distinct vulnerability ids, in document order. */
  vulnerabilityIds?: string[];
  /** Document author, when the format carries one. */
  author?: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function detectFormat(doc: Record<string, unknown>): VexDocumentFormat {
  if (isRecord(doc.document) && isRecord(doc.product_tree) && Array.isArray(doc.vulnerabilities)) {
    return 'CSAF VEX';
  }
  if ('vulnerabilities' in doc && 'bomFormat' in doc) return 'CycloneDX VEX';
  if ('statements' in doc) return 'OpenVEX';
  return 'VEX JSON';
}

function detectAuthor(doc: Record<string, unknown>): string | undefined {
  if (typeof doc.author === 'string' && doc.author.trim()) return doc.author.trim();

  const csafDoc = isRecord(doc.document) ? doc.document : {};
  const publisher = isRecord(csafDoc.publisher) ? csafDoc.publisher : {};
  if (typeof publisher.name === 'string' && publisher.name.trim()) return publisher.name.trim();

  const metadata = isRecord(doc.metadata) ? doc.metadata : {};
  const supplier = isRecord(metadata.supplier) ? metadata.supplier : {};
  if (typeof supplier.name === 'string' && supplier.name.trim()) return supplier.name.trim();

  const authors = isRecord(doc.metadata) ? doc.metadata.authors : undefined;
  if (Array.isArray(authors)) {
    const first = authors.find((a) => isRecord(a) && typeof a.name === 'string' && a.name.trim());
    if (isRecord(first) && typeof first.name === 'string') return first.name.trim();
  }
  return undefined;
}

/** CycloneDX / CSAF both key vulnerabilities off `id` or `cve`. */
function vulnIdsFromVulnerabilities(entries: unknown[]): string[] {
  const ids: string[] = [];
  for (const entry of entries) {
    if (!isRecord(entry)) continue;
    const id = entry.id ?? entry.cve;
    if (typeof id === 'string' && id.trim()) ids.push(id.trim());
  }
  return ids;
}

/** OpenVEX nests the id under `vulnerability.name`, with two legacy spellings. */
function vulnIdsFromStatements(entries: unknown[]): string[] {
  const ids: string[] = [];
  for (const entry of entries) {
    if (!isRecord(entry)) continue;
    const vulnerability = entry.vulnerability;
    const name = isRecord(vulnerability) ? vulnerability.name : undefined;
    const id = name ?? entry.vulnerability_id ?? entry.vuln_id;
    if (typeof id === 'string' && id.trim()) ids.push(id.trim());
  }
  return ids;
}

/**
 * Count the statements the server will produce, not the top-level entries.
 *
 * A CycloneDX vulnerability with three `affects[]` refs becomes three
 * statements, and an OpenVEX statement listing two products becomes two —
 * reporting "1 vulnerability" where the import writes six rows would make the
 * preview useless as a sanity check.
 */
function countStatements(doc: Record<string, unknown>, format: VexDocumentFormat): number {
  if (format === 'OpenVEX') {
    const statements = Array.isArray(doc.statements) ? doc.statements : [];
    return statements.reduce<number>((sum, statement) => {
      if (!isRecord(statement)) return sum;
      const products = Array.isArray(statement.products) ? statement.products.length : 0;
      return sum + Math.max(1, products);
    }, 0);
  }

  const vulnerabilities = Array.isArray(doc.vulnerabilities) ? doc.vulnerabilities : [];
  if (format === 'CSAF VEX') {
    // CSAF fans out over product_status buckets; without resolving the
    // product_tree the honest count is one per vulnerability entry.
    return vulnerabilities.filter(isRecord).length;
  }
  return vulnerabilities.reduce<number>((sum, vulnerability) => {
    if (!isRecord(vulnerability)) return sum;
    const affects = Array.isArray(vulnerability.affects) ? vulnerability.affects : [];
    let perVulnerability = 0;
    for (const affected of affects) {
      if (!isRecord(affected)) continue;
      const versions = Array.isArray(affected.versions) ? affected.versions.length : 0;
      perVulnerability += Math.max(1, versions);
    }
    return sum + Math.max(1, perVulnerability);
  }, 0);
}

export function previewVexDocument(text: string): VexDocumentPreview {
  const trimmed = (text ?? '').trim();
  if (!trimmed) return { ok: false };

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return { ok: false, error: 'Not valid JSON — check for a truncated paste or a trailing comma.' };
  }
  if (!isRecord(parsed)) {
    return { ok: false, error: 'A VEX document must be a JSON object.' };
  }

  const format = detectFormat(parsed);
  const vulnerabilityIds =
    format === 'OpenVEX'
      ? vulnIdsFromStatements(Array.isArray(parsed.statements) ? parsed.statements : [])
      : vulnIdsFromVulnerabilities(Array.isArray(parsed.vulnerabilities) ? parsed.vulnerabilities : []);

  const statementCount = countStatements(parsed, format);
  if (statementCount === 0) {
    return {
      ok: false,
      format,
      error:
        format === 'OpenVEX'
          ? 'No statements found — OpenVEX documents need a non-empty "statements" array.'
          : 'No vulnerabilities found — nothing would be imported.',
    };
  }

  return {
    ok: true,
    format,
    statementCount,
    vulnerabilityIds: Array.from(new Set(vulnerabilityIds)),
    author: detectAuthor(parsed),
  };
}
