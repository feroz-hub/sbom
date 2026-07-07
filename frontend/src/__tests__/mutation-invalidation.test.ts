/**
 * Architectural invariant: every `useMutation` that talks to the server
 * MUST invalidate at least one query key on success (or be explicitly
 * marked `// @no-invalidation-needed` if the mutation has no
 * server-side cache effect — e.g. test-connection probes).
 *
 * Why this test exists
 * --------------------
 * The same one-line bug kept shipping: a mutation lands, but a sibling
 * list view (sidebar, dashboard tile, command palette, …) stays stale
 * until the user hits F5. The May 2026 audit fixed five instances;
 * this test is the seatbelt so the sixth never ships.
 *
 * How it works
 * ------------
 * Scans every non-test `.ts`/`.tsx` under `frontend/src`. For each
 * `useMutation(...)` call, walks forward through paren depth to
 * extract the block. The block must contain one of:
 *   - `invalidateQueries(`
 *   - `setQueryData(` (used for cache priming where consumers read the
 *     same key — covers the `useUpdateAiCredentialSettings` pattern)
 *   - `refetchQueries(`
 *   - any helper named `invalidate*` (the centralised helpers in
 *     `lib/queryInvalidation.ts` and `invalidateAllAiFixes`)
 *
 * Or be preceded (within 250 chars) by `// @no-invalidation-needed`.
 *
 * See: docs/cache-invalidation-audit.md, CLAUDE.md → "TanStack Query —
 * mutation invalidation".
 */

import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const SRC_ROOT = resolve(__dirname, '..');

function walkFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === '__tests__') continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...walkFiles(full));
    } else if (
      (entry.name.endsWith('.ts') || entry.name.endsWith('.tsx')) &&
      !entry.name.endsWith('.test.ts') &&
      !entry.name.endsWith('.test.tsx') &&
      !entry.name.endsWith('.spec.ts') &&
      !entry.name.endsWith('.spec.tsx') &&
      !entry.name.endsWith('.d.ts')
    ) {
      out.push(full);
    }
  }
  return out;
}

/**
 * Find every `useMutation` call site in `content` and return the byte
 * offsets of the call's opening paren and matching closing paren.
 */
function findMutationBlocks(content: string): { start: number; end: number }[] {
  const blocks: { start: number; end: number }[] = [];
  // Match `useMutation`, optionally followed by `<…generic…>`, then `(`.
  // The codebase doesn't use nested generics in `useMutation` calls today;
  // `[^>]*` is sufficient.
  const pattern = /\buseMutation\s*(?:<[^>]*>)?\s*\(/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(content)) !== null) {
    const openParenIdx = match.index + match[0].length - 1;
    const end = findMatchingClose(content, openParenIdx);
    if (end !== -1) {
      blocks.push({ start: openParenIdx, end });
    }
  }
  return blocks;
}

/**
 * Walk forward from `openIdx` (which must point at `(`) and return the
 * index of the matching `)`. Tracks string/template/comment context so
 * a `)` inside a string literal doesn't fool the counter.
 */
function findMatchingClose(s: string, openIdx: number): number {
  let depth = 0;
  let i = openIdx;
  let inStr: '"' | "'" | '`' | null = null;
  let inLineComment = false;
  let inBlockComment = false;

  while (i < s.length) {
    const c = s[i];
    const next = s[i + 1];

    if (inLineComment) {
      if (c === '\n') inLineComment = false;
      i++;
      continue;
    }
    if (inBlockComment) {
      if (c === '*' && next === '/') {
        inBlockComment = false;
        i += 2;
        continue;
      }
      i++;
      continue;
    }
    if (inStr) {
      if (c === '\\') { i += 2; continue; }
      if (c === inStr) inStr = null;
      i++;
      continue;
    }
    if (c === '/' && next === '/') { inLineComment = true; i += 2; continue; }
    if (c === '/' && next === '*') { inBlockComment = true; i += 2; continue; }
    if (c === '"' || c === "'" || c === '`') { inStr = c; i++; continue; }

    if (c === '(') depth++;
    else if (c === ')') {
      depth--;
      if (depth === 0) return i;
    }
    i++;
  }
  return -1;
}

// Match `setQueryData`, `refetchQueries`, or any identifier starting with
// `invalidate` (`invalidateQueries` / `invalidateSbomLists` / a local
// `invalidate()` alias). The marker escape hatch covers cases where a
// caller wants to opt out.
const INVALIDATION_TOKEN = /(?:setQueryData|refetchQueries|\binvalidate\w*)\s*\(/;
const MARKER = /@no-invalidation-needed/;

describe('mutation invalidation architectural invariant', () => {
  const files = walkFiles(SRC_ROOT);

  it('walks every source file', () => {
    // Sanity check — if the walker ever returns 0 files the rest of the
    // suite is meaningless. Pin a floor that's well below current size.
    expect(files.length).toBeGreaterThan(50);
  });

  it('every useMutation invalidates or is explicitly marked read-only', () => {
    const violations: string[] = [];

    for (const file of files) {
      const content = readFileSync(file, 'utf-8');
      const blocks = findMutationBlocks(content);
      for (const { start, end } of blocks) {
        const block = content.slice(start, end + 1);
        const preceding = content.slice(Math.max(0, start - 250), start);

        if (MARKER.test(preceding) || MARKER.test(block)) continue;
        if (INVALIDATION_TOKEN.test(block)) continue;

        // Compute 1-based line/col for human-friendly error reporting.
        const upto = content.slice(0, start);
        const line = upto.split('\n').length;
        const rel = file.replace(`${SRC_ROOT}/`, 'src/');
        violations.push(
          `${rel}:${line} — useMutation has no invalidation, ` +
          `no setQueryData / refetchQueries, and no // @no-invalidation-needed marker.`,
        );
      }
    }

    if (violations.length > 0) {
      // Emit the list above the assertion so CI logs are useful even when
      // the assertion's expected/actual diff truncates.
       
      console.error(
        '\nMutation invalidation violations:\n  ' + violations.join('\n  ') + '\n',
      );
    }
    expect(violations).toEqual([]);
  });
});
