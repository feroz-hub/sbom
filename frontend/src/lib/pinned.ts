// localStorage-backed pinning store for SBOMs and runs.
//
// Separate keys per kind so a stale pin in one bucket can't confuse the
// other. Versioned so we can migrate later. Cross-component sync via a
// `window` custom event — pages listening can refresh without a global store.

import { useCallback, useEffect, useState } from 'react';

export type PinnedKind = 'sbom' | 'run';

export interface PinnedItem {
  id: number;
  label: string;
  href: string;
  pinnedAt: number;
}

interface PinStorage {
  version: number;
  items: PinnedItem[];
}

const STORAGE_VERSION = 1;
const MAX_PINS_PER_KIND = 12;
const STORAGE_KEY: Record<PinnedKind, string> = {
  sbom: 'pinned-sboms-v1',
  run: 'pinned-runs-v1',
};
const CHANGE_EVENT: Record<PinnedKind, string> = {
  sbom: 'sbom:pinned-sboms-changed',
  run: 'sbom:pinned-runs-changed',
};

function read(kind: PinnedKind): PinnedItem[] {
  if (typeof window === 'undefined') return [];
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY[kind]);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as PinStorage;
    if (!parsed || parsed.version !== STORAGE_VERSION || !Array.isArray(parsed.items)) return [];
    return parsed.items.filter(
      (i): i is PinnedItem =>
        i != null &&
        typeof i.id === 'number' &&
        typeof i.label === 'string' &&
        typeof i.href === 'string' &&
        typeof i.pinnedAt === 'number',
    );
  } catch {
    return [];
  }
}

function write(kind: PinnedKind, items: PinnedItem[]) {
  if (typeof window === 'undefined') return;
  try {
    const payload: PinStorage = { version: STORAGE_VERSION, items };
    window.localStorage.setItem(STORAGE_KEY[kind], JSON.stringify(payload));
    // Fire event so other tabs / components hear the change immediately.
    window.dispatchEvent(new CustomEvent(CHANGE_EVENT[kind]));
  } catch {
    // QuotaExceeded / private mode — silently drop; pins are optional UX.
  }
}

export function listPinned(kind: PinnedKind): PinnedItem[] {
  return read(kind).sort((a, b) => b.pinnedAt - a.pinnedAt);
}

export function isPinned(kind: PinnedKind, id: number): boolean {
  return read(kind).some((i) => i.id === id);
}

export function pin(kind: PinnedKind, item: Omit<PinnedItem, 'pinnedAt'>): void {
  const existing = read(kind).filter((i) => i.id !== item.id);
  const next: PinnedItem[] = [{ ...item, pinnedAt: Date.now() }, ...existing].slice(
    0,
    MAX_PINS_PER_KIND,
  );
  write(kind, next);
}

export function unpin(kind: PinnedKind, id: number): void {
  write(kind, read(kind).filter((i) => i.id !== id));
}

export function togglePinned(kind: PinnedKind, item: Omit<PinnedItem, 'pinnedAt'>): boolean {
  const exists = isPinned(kind, item.id);
  if (exists) {
    unpin(kind, item.id);
    return false;
  }
  pin(kind, item);
  return true;
}

/**
 * React hook that mirrors the localStorage pinned list for a given kind and
 * stays in sync with mutations from other components / tabs.
 */
export function usePinned(kind: PinnedKind): {
  items: PinnedItem[];
  isPinned: (id: number) => boolean;
  toggle: (item: Omit<PinnedItem, 'pinnedAt'>) => boolean;
  remove: (id: number) => void;
} {
  const [items, setItems] = useState<PinnedItem[]>(() => listPinned(kind));

  // Refresh on cross-component pin/unpin events.
  useEffect(() => {
    const refresh = () => setItems(listPinned(kind));
    window.addEventListener(CHANGE_EVENT[kind], refresh);
    // Cross-tab sync: storage event fires when another tab writes.
    const onStorage = (e: StorageEvent) => {
      if (e.key === STORAGE_KEY[kind]) refresh();
    };
    window.addEventListener('storage', onStorage);
    return () => {
      window.removeEventListener(CHANGE_EVENT[kind], refresh);
      window.removeEventListener('storage', onStorage);
    };
  }, [kind]);

  const has = useCallback((id: number) => items.some((i) => i.id === id), [items]);
  const toggle = useCallback(
    (item: Omit<PinnedItem, 'pinnedAt'>) => togglePinned(kind, item),
    [kind],
  );
  const remove = useCallback((id: number) => unpin(kind, id), [kind]);

  return { items, isPinned: has, toggle, remove };
}
