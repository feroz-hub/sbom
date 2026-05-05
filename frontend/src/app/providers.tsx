'use client';

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useState, type ReactNode } from 'react';
import { ToastProvider } from '@/hooks/useToast';
import { ThemeProvider } from '@/components/theme/ThemeProvider';
import { CommandPalette } from '@/components/layout/CommandPalette';
import { KeyboardCheatsheet } from '@/components/layout/KeyboardCheatsheet';
import { AiBatchProgressProvider } from '@/components/ai-fixes/GlobalAiBatchProgress';

export function Providers({ children }: { children: ReactNode }) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            // 30s was too aggressive: navigating away for >30s and back
            // triggered a full skeleton cycle on return because the
            // cache was already stale. Dashboard counts / trend data
            // change minute-to-minute at most, so 5 min is the right
            // budget. Routes that need fresher data (analysis runs in
            // flight) can override per-query.
            staleTime: 5 * 60_000,
            // Window-focus refetch double-counts work when the same tab
            // navigates away and back — the route remount already
            // refetches when staleTime expires.
            refetchOnWindowFocus: false,
            retry: 1,
          },
        },
      })
  );

  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <ToastProvider>
          <AiBatchProgressProvider>
            {children}
            <CommandPalette />
            <KeyboardCheatsheet />
          </AiBatchProgressProvider>
        </ToastProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}
