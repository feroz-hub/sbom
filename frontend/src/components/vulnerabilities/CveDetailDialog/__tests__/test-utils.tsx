/**
 * RTL helpers — render-with-providers and a writable navigator.clipboard
 * shim. Lives next to the tests so each file can pick what it needs.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, type RenderOptions } from '@testing-library/react';
import type { ReactElement, ReactNode } from 'react';
import { ToastProvider } from '@/hooks/useToast';

/** Brand-new QueryClient per call so test caches don't leak. */
export function newQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0, staleTime: 0 },
      mutations: { retry: false },
    },
  });
}

interface ProvidersProps {
  client?: QueryClient;
  children: ReactNode;
}

export function Providers({ client, children }: ProvidersProps) {
  const qc = client ?? newQueryClient();
  return (
    <QueryClientProvider client={qc}>
      <ToastProvider>{children}</ToastProvider>
    </QueryClientProvider>
  );
}

export function renderWithProviders(
  ui: ReactElement,
  opts?: RenderOptions & { client?: QueryClient },
) {
  const { client, ...rest } = opts ?? {};
  return render(ui, {
    wrapper: ({ children }) => <Providers client={client}>{children}</Providers>,
    ...rest,
  });
}

/** Writable ``navigator.clipboard`` shim so copy buttons can be exercised. */
export function installClipboardStub(): { writes: string[] } {
  const writes: string[] = [];
  Object.defineProperty(navigator, 'clipboard', {
    configurable: true,
    value: {
      writeText: (s: string) => {
        writes.push(s);
        return Promise.resolve();
      },
    },
  });
  return { writes };
}
