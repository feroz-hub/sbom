import { describe, expect, it } from 'vitest';
import {
  FULL_DETAIL,
  NOT_FOUND_DETAIL,
  PARTIAL_DETAIL,
  UNREACHABLE_DETAIL,
} from './fixtures';
import { selectDialogState } from '../states';

const baseQuery = { data: undefined, error: null, isLoading: false };

describe('selectDialogState — dialog state mapper', () => {
  it('returns "loading" when no rawId is set (dialog closed)', () => {
    expect(selectDialogState({ rawId: null, query: baseQuery })).toEqual({ kind: 'loading' });
  });

  it('returns "unrecognized" when the frontend classifier rejects the id (no fetch even attempted)', () => {
    const s = selectDialogState({ rawId: 'FOOBAR-123', query: baseQuery });
    expect(s.kind).toBe('unrecognized');
    if (s.kind === 'unrecognized') {
      expect(s.rawId).toBe('FOOBAR-123');
      expect(s.supported.length).toBeGreaterThan(0);
    }
  });

  it('returns "loading" when query is in flight and no data yet', () => {
    expect(
      selectDialogState({
        rawId: 'CVE-2099-9001',
        query: { data: undefined, error: null, isLoading: true },
      }),
    ).toEqual({ kind: 'loading' });
  });

  it('maps backend status=ok → kind=ok with the data passed through', () => {
    const s = selectDialogState({
      rawId: 'CVE-2099-9001',
      query: { data: FULL_DETAIL, error: null, isLoading: false },
    });
    expect(s.kind).toBe('ok');
    if (s.kind === 'ok') expect(s.data).toBe(FULL_DETAIL);
  });

  it('maps backend status=partial → kind=partial', () => {
    const s = selectDialogState({
      rawId: 'CVE-2099-9001',
      query: { data: PARTIAL_DETAIL, error: null, isLoading: false },
    });
    expect(s.kind).toBe('partial');
  });

  it('maps backend status=not_found → kind=not_found', () => {
    const s = selectDialogState({
      rawId: 'CVE-2099-9001',
      query: { data: NOT_FOUND_DETAIL, error: null, isLoading: false },
    });
    expect(s.kind).toBe('not_found');
  });

  it('maps backend status=unreachable → kind=unreachable with canRetry', () => {
    const s = selectDialogState({
      rawId: 'CVE-2099-9001',
      query: { data: UNREACHABLE_DETAIL, error: null, isLoading: false },
    });
    expect(s.kind).toBe('unreachable');
    if (s.kind === 'unreachable') expect(s.canRetry).toBe(true);
  });

  it('falls back to "unreachable" when fetch errors out and no data', () => {
    const s = selectDialogState({
      rawId: 'CVE-2099-9001',
      query: { data: undefined, error: new Error('network'), isLoading: false },
    });
    expect(s.kind).toBe('unreachable');
  });

  it('treats a 400 with CVE_VAL_E001_UNRECOGNIZED_ID as "unrecognized" (server is the canary)', () => {
    const err = Object.assign(new Error('not recognized'), {
      status: 400,
      code: 'CVE_VAL_E001_UNRECOGNIZED_ID',
    });
    // ``rawId`` is well-formed by the frontend regex but the server still
    // rejected it (e.g. the frontend mirror drifted from the backend).
    const s = selectDialogState({
      rawId: 'CVE-2099-9001',
      query: { data: undefined, error: err, isLoading: false },
    });
    expect(s.kind).toBe('unrecognized');
  });
});
