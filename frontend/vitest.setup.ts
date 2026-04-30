/**
 * Vitest setup — runs before every test file.
 *
 *   * Adds jest-dom matchers (toBeInTheDocument, toHaveTextContent, …)
 *   * Provides a default NEXT_PUBLIC_API_URL so modules that call
 *     ``resolveBaseUrl()`` at import time don't throw inside the harness.
 *   * Provides a no-op ``ResizeObserver`` because some Radix-style focus
 *     guards (and our scrollable Dialog body measurement) call it.
 *   * Provides ``window.matchMedia`` because Tailwind ``motion-reduce`` and
 *     reduced-motion checks call it on mount.
 */

import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';

// RTL v16 only auto-registers cleanup when ``globalThis.afterEach`` is
// present at import time, which under vitest requires ``globals: true``.
// We don't enable globals (cleaner imports), so we wire cleanup ourselves.
afterEach(() => {
  cleanup();
});

if (typeof process !== 'undefined' && process.env) {
  process.env.NEXT_PUBLIC_API_URL ??= 'http://test.local';
}

// jsdom-only shims. Guarded so the file works under node-env tests too.
if (typeof window !== 'undefined') {
  if (typeof window.matchMedia !== 'function') {
    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      value: (query: string) => ({
        matches: false,
        media: query,
        onchange: null,
        addListener: () => {},
        removeListener: () => {},
        addEventListener: () => {},
        removeEventListener: () => {},
        dispatchEvent: () => false,
      }),
    });
  }

  const g = globalThis as unknown as { ResizeObserver?: unknown };
  if (typeof g.ResizeObserver === 'undefined') {
    class ResizeObserverStub {
      observe(): void {}
      unobserve(): void {}
      disconnect(): void {}
    }
    g.ResizeObserver = ResizeObserverStub;
  }
}
