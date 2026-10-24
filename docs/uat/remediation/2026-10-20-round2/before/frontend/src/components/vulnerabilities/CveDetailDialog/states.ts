/**
 * Discriminated union the dialog renders against. The mapper
 * ``selectDialogState`` is pure (TanStack-Query state in, dialog state out)
 * so it's trivially testable and the components below stay declarative.
 */

import type {
  CveDetail,
  CveDetailWithContext,
  CveUnrecognizedIdEnvelope,
} from '@/types';

import { SUPPORTED_VULN_FORMATS, resolveVulnId } from '@/lib/vulnIds';

export type DialogState =
  | { kind: 'loading' }
  | { kind: 'ok'; data: CveDetail | CveDetailWithContext }
  | { kind: 'partial'; data: CveDetail | CveDetailWithContext }
  | { kind: 'not_found'; data: CveDetail | CveDetailWithContext }
  | {
      kind: 'unreachable';
      data: CveDetail | CveDetailWithContext | null;
      canRetry: true;
    }
  | { kind: 'unrecognized'; rawId: string; supported: readonly string[] }
  | { kind: 'fatal'; message: string };

/** Slim view of the TanStack-Query result the mapper consumes. */
export interface QueryView {
  data: CveDetail | CveDetailWithContext | undefined;
  error: Error | null;
  isLoading: boolean;
}

interface MapperInput {
  rawId: string | null;
  /**
   * CVE aliases from the row seed. Lets the mapper resolve a source-specific
   * advisory id (e.g. `DEBIAN-CVE-*`) to its canonical CVE before deciding
   * `unrecognized` — the same resolution the fetch uses, so they can't drift.
   */
  aliases?: readonly string[] | null;
  query: QueryView;
}

const ERR_UNRECOGNIZED = 'CVE_VAL_E001_UNRECOGNIZED_ID';

/**
 * Map TanStack-Query state + classifier verdict to the dialog state.
 *
 * Precedence:
 *   1. ``rawId`` is missing → ``loading`` (the dialog is closed; this is
 *      the harmless "no active CVE" path).
 *   2. Frontend resolver can't map ``rawId`` to a supported canonical id →
 *      short-circuit ``unrecognized`` (no fetch is even attempted).
 *   3. Backend returned a 400 with the unrecognized envelope → same.
 *   4. Query in flight → ``loading``.
 *   5. Query returned data → branch on ``data.status``.
 *   6. Network error / unparseable → ``unreachable`` if the row data
 *      gives us *something* to fall back on, ``fatal`` otherwise.
 */
export function selectDialogState({ rawId, aliases, query }: MapperInput): DialogState {
  if (!rawId) return { kind: 'loading' };

  // Resolve source-specific aliases (DEBIAN-CVE-* → CVE-*) before rejecting.
  // Only a genuinely unsupported id short-circuits to the banner; the raw id
  // the user clicked is echoed so the banner keeps its provenance.
  const resolved = resolveVulnId(rawId, { aliases: aliases ?? null });
  if (!resolved.supported) {
    return { kind: 'unrecognized', rawId: resolved.raw, supported: SUPPORTED_VULN_FORMATS };
  }

  const envelope = unrecognizedEnvelopeOf(query.error);
  if (envelope) {
    return {
      kind: 'unrecognized',
      rawId: envelope.raw_id,
      supported: envelope.supported_formats,
    };
  }

  if (query.isLoading && !query.data) {
    return { kind: 'loading' };
  }

  if (query.data) {
    return statusToState(query.data);
  }

  if (query.error) {
    return {
      kind: 'unreachable',
      data: null,
      canRetry: true,
    };
  }

  return { kind: 'loading' };
}

function statusToState(data: CveDetail | CveDetailWithContext): DialogState {
  switch (data.status) {
    case 'ok':
      return { kind: 'ok', data };
    case 'partial':
      return { kind: 'partial', data };
    case 'not_found':
      return { kind: 'not_found', data };
    case 'unreachable':
      return { kind: 'unreachable', data, canRetry: true };
    default: {
      // Defensive: a future server-side status we don't recognise yet.
      // Treat as ``fatal`` so the user sees the report-this affordance
      // rather than blank UI.
      const _exhaust: never = data.status;
      void _exhaust;
      return { kind: 'fatal', message: `unknown status: ${data.status}` };
    }
  }
}

/**
 * Pull the structured 400 envelope out of a TanStack-Query error if the
 * server returned one. ``HttpError`` from ``lib/api`` exposes ``status``
 * and ``code`` but not the full body — so we also accept errors whose
 * ``message`` parses as the envelope JSON (defensive).
 */
function unrecognizedEnvelopeOf(
  err: Error | null,
): CveUnrecognizedIdEnvelope | null {
  if (!err) return null;
  const status = (err as { status?: number }).status ?? 0;
  const code = (err as { code?: string }).code;
  if (status === 400 && code === ERR_UNRECOGNIZED) {
    // The HttpError class only carries status + code; we don't have the
    // raw_id / supported_formats in the error itself. Fall back to the
    // frontend constants when the body is unavailable. (When the API
    // layer learns to surface the full body, we'll plumb it through.)
    return {
      error_code: ERR_UNRECOGNIZED,
      message: err.message,
      raw_id: '',
      supported_formats: [...SUPPORTED_VULN_FORMATS],
      retryable: false,
    };
  }
  return null;
}
