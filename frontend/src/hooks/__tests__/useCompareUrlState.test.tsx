// @vitest-environment jsdom
/**
 * URL state hook round-trip tests.
 *
 * The hook is the source of truth for compare-page state (ADR-0008 §4 / §8).
 * Every parsable param has a default; every setter writes to the URL via the
 * mocked Next router. We exercise the round-trip and the push/replace
 * semantics specifically — getting those wrong breaks the back button.
 */

import { describe, expect, it, vi, beforeEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useCompareUrlState } from '@/hooks/useCompareUrlState';
import { createNavigationState } from '@/components/compare/__tests__/test-utils';

let nav = createNavigationState();

vi.mock('next/navigation', () => ({
  useRouter: () => nav.router,
  useSearchParams: () => nav.params,
  usePathname: () => nav.pathname(),
}));

beforeEach(() => {
  nav = createNavigationState();
});

describe('useCompareUrlState — defaults', () => {
  it('returns null run ids and findings tab when URL is empty', () => {
    const { result } = renderHook(() => useCompareUrlState());
    expect(result.current.runA).toBeNull();
    expect(result.current.runB).toBeNull();
    expect(result.current.tab).toBe('findings');
    expect(Array.from(result.current.changeKinds).sort()).toEqual([
      'added',
      'resolved',
      'severity_changed',
    ]);
    expect(result.current.kevOnly).toBe(false);
    expect(result.current.fixAvailable).toBe(false);
    expect(result.current.showUnchanged).toBe(false);
    expect(result.current.q).toBe('');
  });
});

describe('useCompareUrlState — parsing', () => {
  it('parses run_a and run_b as positive ints; rejects garbage', () => {
    nav = createNavigationState('run_a=5&run_b=8');
    const { result } = renderHook(() => useCompareUrlState());
    expect(result.current.runA).toBe(5);
    expect(result.current.runB).toBe(8);

    nav = createNavigationState('run_a=-3&run_b=abc');
    const { result: r2 } = renderHook(() => useCompareUrlState());
    expect(r2.current.runA).toBeNull();
    expect(r2.current.runB).toBeNull();
  });

  it('parses tab from canonical values; falls back to findings', () => {
    nav = createNavigationState('tab=components');
    expect(renderHook(() => useCompareUrlState()).result.current.tab).toBe('components');

    nav = createNavigationState('tab=delta');
    expect(renderHook(() => useCompareUrlState()).result.current.tab).toBe('delta');

    nav = createNavigationState('tab=garbage');
    expect(renderHook(() => useCompareUrlState()).result.current.tab).toBe('findings');
  });

  it('parses change-kind set; empty string yields empty set', () => {
    nav = createNavigationState('change=added,resolved');
    const r = renderHook(() => useCompareUrlState()).result;
    expect(Array.from(r.current.changeKinds).sort()).toEqual(['added', 'resolved']);

    nav = createNavigationState('change=');
    const r2 = renderHook(() => useCompareUrlState()).result;
    expect(r2.current.changeKinds.size).toBe(0);
  });

  it('parses booleans for kev_only / fix_available / show_unchanged', () => {
    nav = createNavigationState('kev_only=true&fix_available=1&show_unchanged=true');
    const r = renderHook(() => useCompareUrlState()).result;
    expect(r.current.kevOnly).toBe(true);
    expect(r.current.fixAvailable).toBe(true);
    expect(r.current.showUnchanged).toBe(true);
  });
});

describe('useCompareUrlState — setters', () => {
  it('setRuns PUSHES history (navigation event, not filter)', () => {
    const { result } = renderHook(() => useCompareUrlState());
    act(() => result.current.setRuns(7, 9));
    expect(nav.calls.at(-1)?.method).toBe('push');
    expect(nav.calls.at(-1)?.href).toContain('run_a=7');
    expect(nav.calls.at(-1)?.href).toContain('run_b=9');
  });

  it('setTab PUSHES; filter toggles REPLACE', () => {
    const { result } = renderHook(() => useCompareUrlState());
    act(() => result.current.setTab('components'));
    expect(nav.calls.at(-1)?.method).toBe('push');

    act(() => result.current.setKevOnly(true));
    expect(nav.calls.at(-1)?.method).toBe('replace');
    expect(nav.calls.at(-1)?.href).toContain('kev_only=true');
  });

  it('default tab is omitted from the URL (cleaner share links)', () => {
    const { result } = renderHook(() => useCompareUrlState());
    act(() => result.current.setTab('findings'));
    expect(nav.calls.at(-1)?.href).not.toContain('tab=findings');
  });

  it('default change-kind set is omitted from the URL', () => {
    const { result } = renderHook(() => useCompareUrlState());
    act(() =>
      result.current.setChangeKinds(
        new Set(['added', 'resolved', 'severity_changed']),
      ),
    );
    expect(nav.calls.at(-1)?.href).not.toContain('change=');
  });

  it('toggleChangeKind adds and removes', () => {
    nav = createNavigationState('change=added,resolved');
    const { result } = renderHook(() => useCompareUrlState());
    act(() => result.current.toggleChangeKind('severity_changed'));
    // Was added → URL now contains the default set, which is encoded as no
    // ``change`` param at all.
    expect(nav.calls.at(-1)?.href).not.toContain('change=');

    nav = createNavigationState('change=added');
    const { result: r2 } = renderHook(() => useCompareUrlState());
    act(() => r2.current.toggleChangeKind('added'));
    expect(nav.calls.at(-1)?.href).toContain('change=');
    expect(nav.calls.at(-1)?.href).not.toContain('added');
  });

  it('swap reverses run_a and run_b', () => {
    nav = createNavigationState('run_a=3&run_b=4');
    const { result } = renderHook(() => useCompareUrlState());
    act(() => result.current.swap());
    expect(nav.calls.at(-1)?.href).toContain('run_a=4');
    expect(nav.calls.at(-1)?.href).toContain('run_b=3');
  });

  it('setQ writes the q param when non-empty, deletes it otherwise', () => {
    const { result } = renderHook(() => useCompareUrlState());
    act(() => result.current.setQ('log4j'));
    expect(nav.calls.at(-1)?.href).toContain('q=log4j');

    act(() => result.current.setQ(''));
    expect(nav.calls.at(-1)?.href).not.toContain('q=');
  });
});
