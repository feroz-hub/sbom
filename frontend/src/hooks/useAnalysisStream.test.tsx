// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, renderHook, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return { ...actual, BASE_URL: 'http://test.local' };
});

import { useAnalysisStream } from './useAnalysisStream';

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0, staleTime: 0 } },
  });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

describe('useAnalysisStream', () => {
  beforeEach(() => {
    sessionStorage.clear();
    sessionStorage.setItem('sbom_active_tenant_id', '7');
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        body: {
          getReader: () => ({
            read: vi.fn().mockResolvedValue({ done: true, value: undefined }),
            releaseLock: vi.fn(),
          }),
        },
      }),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    sessionStorage.clear();
  });

  it('guards duplicate manual starts for the same SBOM', async () => {
    const { result } = renderHook(() => useAnalysisStream(42), { wrapper });

    act(() => {
      void result.current.startAnalysis();
      void result.current.startAnalysis();
    });

    await waitFor(() => expect(globalThis.fetch).toHaveBeenCalledTimes(1));
    expect(globalThis.fetch).toHaveBeenCalledWith(
      'http://test.local/api/sboms/42/analyze/stream',
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          'Content-Type': 'application/json',
          'Idempotency-Key': expect.stringMatching(/^analysis-sbom-42-/),
        }),
      }),
    );
  });

  it('sends the active tenant on the stream request', async () => {
    const { result } = renderHook(() => useAnalysisStream(42), { wrapper });

    await act(async () => {
      await result.current.startAnalysis();
    });

    expect(globalThis.fetch).toHaveBeenCalledWith(
      'http://test.local/api/sboms/42/analyze/stream',
      expect.objectContaining({
        headers: expect.objectContaining({ 'X-Tenant-ID': '7' }),
      }),
    );
  });

  it('sends no request and reports an inline error when no tenant is selected', async () => {
    sessionStorage.removeItem('sbom_active_tenant_id');
    const { result } = renderHook(() => useAnalysisStream(42), { wrapper });

    await act(async () => {
      await result.current.startAnalysis();
    });

    expect(globalThis.fetch).not.toHaveBeenCalled();
    expect(result.current.state.phase).toBe('error');
    expect(result.current.state.error).toBe('Select a tenant before running analysis.');
  });

  it('uses the newly selected tenant on the next request after a tenant switch', async () => {
    const { result } = renderHook(() => useAnalysisStream(42), { wrapper });

    await act(async () => {
      await result.current.startAnalysis();
    });

    sessionStorage.setItem('sbom_active_tenant_id', '1');

    await act(async () => {
      await result.current.startAnalysis();
    });

    const calls = (globalThis.fetch as unknown as ReturnType<typeof vi.fn>).mock.calls;
    expect(calls).toHaveLength(2);
    expect(calls[0][1].headers['X-Tenant-ID']).toBe('7');
    expect(calls[1][1].headers['X-Tenant-ID']).toBe('1');
  });
});
