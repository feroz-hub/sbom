/**
 * Centralized invalidation helpers — every mutation that creates, updates, or
 * deletes a server resource is expected to call one of these in onSuccess.
 *
 * Keeping the "which keys does this entity touch" mapping in one place
 * prevents new mutations from silently leaving sibling list views stale
 * (the classic "SBOM uploaded but main table doesn't update" bug class).
 *
 * Prefix-match note: TanStack invalidates by array-prefix, so
 * `invalidateQueries({ queryKey: ['sboms'] })` also catches
 * `['sboms', 'for-schedules']` and any future sub-keys.
 */

import type { QueryClient } from '@tanstack/react-query';

export function invalidateSbomLists(qc: QueryClient): void {
  qc.invalidateQueries({ queryKey: ['sboms'] });
  qc.invalidateQueries({ queryKey: ['sidebar-recent-sboms'] });
  qc.invalidateQueries({ queryKey: ['recent-sboms'] });
  qc.invalidateQueries({ queryKey: ['palette-recent-sboms'] });
}

export function invalidateProjectLists(qc: QueryClient): void {
  qc.invalidateQueries({ queryKey: ['projects'] });
}

export function invalidateRunLists(qc: QueryClient): void {
  qc.invalidateQueries({ queryKey: ['runs'] });
}

export function invalidateScheduleLists(qc: QueryClient): void {
  qc.invalidateQueries({ queryKey: ['schedules'] });
  qc.invalidateQueries({ queryKey: ['schedule'] });
}
