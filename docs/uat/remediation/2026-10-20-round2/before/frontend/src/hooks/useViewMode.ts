'use client';

import { useCallback, useState } from 'react';

export type ViewMode = 'list' | 'grid';

/**
 * Remembered list/grid preference for one screen.
 *
 * Persisted per `storageKey` under the same `sbom.*` localStorage convention
 * `usePagination` uses, and read lazily inside `useState` so the first paint
 * already reflects the stored choice — reading it in an effect would flash the
 * default view on every navigation.
 *
 * Every access is wrapped: `localStorage` throws outright in some privacy
 * modes, and a view preference is never worth breaking a page over.
 */
function readStoredMode(key: string | undefined, fallback: ViewMode): ViewMode {
  if (!key || typeof window === 'undefined') return fallback;
  try {
    const raw = window.localStorage.getItem(`sbom.viewmode.${key}`);
    return raw === 'list' || raw === 'grid' ? raw : fallback;
  } catch {
    return fallback;
  }
}

function writeStoredMode(key: string | undefined, mode: ViewMode): void {
  if (!key || typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(`sbom.viewmode.${key}`, mode);
  } catch {
    // ignore quota / privacy-mode errors
  }
}

export function useViewMode(
  storageKey?: string,
  defaultMode: ViewMode = 'list',
): [ViewMode, (mode: ViewMode) => void] {
  const [mode, setMode] = useState<ViewMode>(() => readStoredMode(storageKey, defaultMode));

  const update = useCallback(
    (next: ViewMode) => {
      setMode(next);
      writeStoredMode(storageKey, next);
    },
    [storageKey],
  );

  return [mode, update];
}
