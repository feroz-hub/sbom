// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '@/hooks/useToast';
import { safeReturnPath } from '@/lib/auth';

const routerReplace = vi.hoisted(() => vi.fn());

vi.mock('next/navigation', () => ({
  useRouter: () => ({
    push: vi.fn(),
    replace: routerReplace,
    refresh: vi.fn(),
  }),
}));

const setBootstrapStateMock = vi.fn();
const refreshSessionMock = vi.fn();
const loginMock = vi.fn().mockImplementation(async () => {
  const currentPath = `${window.location.pathname}${window.location.search}`;
  const returnTo = safeReturnPath(currentPath);
  window.location.assign(`/api/auth/login?returnTo=${encodeURIComponent(returnTo)}`);
});
const retryBootstrapMock = vi.fn();

vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => ({
    setBootstrapState: setBootstrapStateMock,
    refreshSession: refreshSessionMock,
    login: loginMock,
    retryBootstrap: retryBootstrapMock,
  }),
}));

import { LoginCallback } from '../LoginCallback';

function wrap(children: ReactNode) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <ToastProvider>{children}</ToastProvider>
    </QueryClientProvider>,
  );
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('LoginCallback component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    refreshSessionMock.mockResolvedValue(undefined);
  });

  it('exchanges code exactly once, cleans URL parameters, and redirects to safe internal destination', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      jsonResponse({ ok: true, returnTo: '/projects' }),
    );
    const replaceStateSpy = vi.spyOn(window.history, 'replaceState');

    window.history.pushState({}, '', '/auth/callback?code=test-code&state=test-state');

    wrap(<LoginCallback />);

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    expect(fetchMock).toHaveBeenCalledWith('/api/auth/callback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: 'test-code', state: 'test-state' }),
    });

    expect(replaceStateSpy).toHaveBeenCalledWith({}, document.title, '/auth/callback');
    expect(refreshSessionMock).toHaveBeenCalledTimes(1);
    expect(routerReplace).toHaveBeenCalledWith('/projects');
  });

  it('rejects external returnTo URLs and defaults to internal root destination', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      jsonResponse({ ok: true, returnTo: 'https://malicious.external/phish' }),
    );
    window.history.pushState({}, '', '/auth/callback?code=test-code&state=test-state');

    wrap(<LoginCallback />);

    await waitFor(() => expect(routerReplace).toHaveBeenCalledWith('/'));
  });

  it('redirects to root when callback API returns /auth/callback as returnTo and never calls /auth/callback', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      jsonResponse({ ok: true, returnTo: '/auth/callback' }),
    );
    window.history.pushState({}, '', '/auth/callback?code=test-code&state=test-state');

    wrap(<LoginCallback />);

    await waitFor(() => expect(routerReplace).toHaveBeenCalledWith('/'));
    expect(routerReplace).not.toHaveBeenCalledWith('/auth/callback');
    expect(routerReplace).not.toHaveBeenCalledWith(expect.stringContaining('/auth/callback'));
  });

  it('redirects to root when callback API returns auth lifecycle targets with query strings', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      jsonResponse({ ok: true, returnTo: '/auth/callback?error=something' }),
    );
    window.history.pushState({}, '', '/auth/callback?code=test-code&state=test-state');

    wrap(<LoginCallback />);

    await waitFor(() => expect(routerReplace).toHaveBeenCalledWith('/'));
    expect(routerReplace).not.toHaveBeenCalledWith(expect.stringContaining('/auth/callback'));
  });

  it('redirects to root when callback API returns lifecycle routes (/logged-out, /verification-required, /access-denied)', async () => {
    for (const target of ['/logged-out', '/verification-required', '/access-denied', '/access-pending']) {
      vi.clearAllMocks();
      vi.spyOn(globalThis, 'fetch').mockResolvedValue(
        jsonResponse({ ok: true, returnTo: `${target}?reason=test` }),
      );
      window.history.pushState({}, '', '/auth/callback?code=test-code&state=test-state');

      wrap(<LoginCallback />);

      await waitFor(() => expect(routerReplace).toHaveBeenCalledWith('/'));
      expect(routerReplace).not.toHaveBeenCalledWith(expect.stringContaining(target));
    }
  });

  it('preserves valid application returnTo destinations with query strings', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      jsonResponse({ ok: true, returnTo: '/sboms/42?tab=components' }),
    );
    window.history.pushState({}, '', '/auth/callback?code=test-code&state=test-state');

    wrap(<LoginCallback />);

    await waitFor(() => expect(routerReplace).toHaveBeenCalledWith('/sboms/42?tab=components'));
  });

  it('handles callback state validation errors cleanly', async () => {
    window.history.pushState({}, '', '/auth/callback?error=invalid_grant');

    wrap(<LoginCallback />);

    expect(await screen.findByText('Authentication Failed')).toBeInTheDocument();
    expect(screen.getAllByText(/Identity Provider error/i)[0]).toBeInTheDocument();
    expect(setBootstrapStateMock).toHaveBeenCalledWith('error', expect.stringContaining('Identity Provider error'));
  });

  it('initiates authorization with returnTo=/ when Sign in again is clicked while browser path is /auth/callback', async () => {
    const user = userEvent.setup();
    const windowObj = window as unknown as Record<string, unknown>;
    const originalLocation = window.location;
    const assignSpy = vi.fn();

    delete windowObj.location;
    windowObj.location = {
      ...originalLocation,
      pathname: '/auth/callback',
      search: '?error=invalid_grant',
      assign: assignSpy,
    };

    try {
      wrap(<LoginCallback />);

      expect(await screen.findByText('Authentication Failed')).toBeInTheDocument();
      const signInButton = screen.getByRole('button', { name: /sign in again/i });
      await user.click(signInButton);

      expect(loginMock).toHaveBeenCalledTimes(1);
      expect(assignSpy).toHaveBeenCalledWith('/api/auth/login?returnTo=%2F');
      expect(assignSpy).not.toHaveBeenCalledWith(expect.stringContaining('/auth/callback'));
    } finally {
      delete windowObj.location;
      windowObj.location = originalLocation;
    }
  });
});
