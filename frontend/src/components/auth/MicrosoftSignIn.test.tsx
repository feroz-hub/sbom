// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { MicrosoftSignIn } from './MicrosoftSignIn';

const msal = vi.hoisted(() => ({ initialize: vi.fn().mockResolvedValue(undefined), loginPopup: vi.fn(), clearCache: vi.fn().mockResolvedValue(undefined), constructor: vi.fn() }));
vi.mock('@azure/msal-browser', () => ({ BrowserCacheLocation: { MemoryStorage: 'memoryStorage' }, PublicClientApplication: class {
  constructor(config: unknown) { msal.constructor(config); }
  initialize = msal.initialize; loginPopup = msal.loginPopup; clearCache = msal.clearCache;
} }));
afterEach(() => { cleanup(); vi.clearAllMocks(); vi.unstubAllGlobals(); });
it('hides Microsoft login when disabled', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({ enabled: false })));
  render(<MicrosoftSignIn />);
  await waitFor(() => expect(fetch).toHaveBeenCalled());
  expect(screen.queryByRole('button')).toBeNull(); expect(msal.initialize).not.toHaveBeenCalled();
});
it('uses memory-only MSAL and sends only the API access token to the BFF', async () => {
  const fetcher = vi.fn().mockResolvedValueOnce(Response.json({ enabled: true, clientId: 'client', authority: 'https://login.microsoftonline.com/directory', redirectUri: 'https://sbom.test/auth/entra-callback', scope: 'api://api/access_as_user' })).mockResolvedValueOnce(Response.json({ status: 'USER_ACCESS_PENDING' }));
  vi.stubGlobal('fetch', fetcher);
  msal.loginPopup.mockResolvedValue({ accessToken: 'api-access', idToken: 'never-send-id-token' });
  render(<MicrosoftSignIn />);
  fireEvent.click(await screen.findByRole('button', { name: 'Sign in with Microsoft' }));
  await waitFor(() => expect(msal.clearCache).toHaveBeenCalled());
  expect(msal.constructor).toHaveBeenCalledWith(expect.objectContaining({ cache: { cacheLocation: 'memoryStorage' } }));
  expect(msal.loginPopup).toHaveBeenCalledWith({ scopes: ['api://api/access_as_user'], prompt: 'select_account' });
  expect(fetcher.mock.calls[1][1].body).toBe(JSON.stringify({ accessToken: 'api-access' }));
});
it('shows safe errors without rendering provider diagnostics', async () => {
  vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('sensitive diagnostics')));
  render(<MicrosoftSignIn />); expect(await screen.findByRole('alert')).not.toHaveTextContent('sensitive');
});
