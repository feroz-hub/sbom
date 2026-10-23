/** Formatting only. Never use a displayed key as a resource selector. */
export function recordIdLabel(kind: string, displayId: unknown): string {
  const valid = typeof displayId === 'number' && Number.isSafeInteger(displayId) && displayId > 0;
  return `${kind ? `${kind} ` : ''}${valid ? `#${displayId}` : '—'}`;
}

/** Old pin labels may contain their own UUID. Keep storage, href and key intact. */
export function cachedRecordLabel(label: string, id: string | number, kind: 'SBOM' | 'Run'): string {
  if (typeof id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)) return label;
  for (const prefix of ['', 'Run ', 'SBOM ']) {
    const reference = `${prefix}#${id}`;
    if (label === reference) return recordIdLabel(kind, undefined);
    for (const separator of [' · ', ' — ']) {
      const suffix = separator + reference;
      if (label.endsWith(suffix)) return label.slice(0, -suffix.length) || recordIdLabel(kind, undefined);
    }
  }
  return label;
}
