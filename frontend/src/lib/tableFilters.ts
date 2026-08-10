/** Case-insensitive substring match; empty query matches everything. */
export function matchesQuery(haystack: string | null | undefined, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return (haystack ?? '').toLowerCase().includes(q);
}

/** True if every token appears somewhere in the combined fields (AND). */
export function matchesMultiField(query: string, fields: (string | null | undefined)[]): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  const tokens = q.split(/\s+/).filter(Boolean);
  const combined = fields.map((f) => (f ?? '').toLowerCase()).join(' ');
  return tokens.every((t) => combined.includes(t));
}
