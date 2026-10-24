import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { constantTimeEqual, createPkce, randomBase64Url, safeReturnPath } from '@/lib/auth/pkce';

describe('authorization code with PKCE', () => {
  it('creates independent state, nonce, verifier, and an S256 challenge', () => {
    const state = randomBase64Url();
    const nonce = randomBase64Url();
    const { verifier, challenge } = createPkce();
    expect(verifier.length).toBeGreaterThanOrEqual(43);
    expect(challenge).toBe(createHash('sha256').update(verifier, 'ascii').digest('base64url'));
    expect(state).not.toBe(nonce);
    expect(state).not.toBe(verifier);
  });

  it('compares OAuth state in constant-time and rejects open redirects', () => {
    expect(constantTimeEqual('valid-state', 'valid-state')).toBe(true);
    expect(constantTimeEqual('valid-state', 'wrong-state')).toBe(false);
  });

  describe('safeReturnPath', () => {
    it('preserves valid application routes and query strings', () => {
      expect(safeReturnPath('/')).toBe('/');
      expect(safeReturnPath('/projects')).toBe('/projects');
      expect(safeReturnPath('/projects?view=all')).toBe('/projects?view=all');
      expect(safeReturnPath('/sboms/42')).toBe('/sboms/42');
      expect(safeReturnPath('/sboms/42?tab=components')).toBe('/sboms/42?tab=components');
      expect(safeReturnPath('/sboms/42?tab=components#section')).toBe('/sboms/42?tab=components#section');
      expect(safeReturnPath('/settings/platform/tenants')).toBe('/settings/platform/tenants');
    });

    it('rejects open redirects and malicious targets', () => {
      expect(safeReturnPath('https://evil.example')).toBe('/');
      expect(safeReturnPath('http://evil.example')).toBe('/');
      expect(safeReturnPath('//evil.example')).toBe('/');
      expect(safeReturnPath('//evil.example.com/projects')).toBe('/');
      expect(safeReturnPath('/\\evil')).toBe('/');
      expect(safeReturnPath('/\\evil.example.com')).toBe('/');
      expect(safeReturnPath('/foo\\bar')).toBe('/');
      expect(safeReturnPath('javascript:alert(1)')).toBe('/');
      expect(safeReturnPath('data:text/html,evil')).toBe('/');
      expect(safeReturnPath('/projects\r\nevil')).toBe('/');
      expect(safeReturnPath('/projects\nevil')).toBe('/');
    });

    it('rejects auth lifecycle routes with or without query strings or subpaths', () => {
      // /auth/callback
      expect(safeReturnPath('/auth/callback')).toBe('/');
      expect(safeReturnPath('/auth/callback?code=foo&state=bar')).toBe('/');
      expect(safeReturnPath('/auth/callback/')).toBe('/');
      expect(safeReturnPath('/auth/callback/subpath')).toBe('/');
      expect(safeReturnPath('/AUTH/CALLBACK')).toBe('/');

      // /logged-out
      expect(safeReturnPath('/logged-out')).toBe('/');
      expect(safeReturnPath('/logged-out?anything')).toBe('/');
      expect(safeReturnPath('/logged-out/')).toBe('/');

      // other auth lifecycle routes
      expect(safeReturnPath('/verification-required')).toBe('/');
      expect(safeReturnPath('/verification-required?anything')).toBe('/');
      expect(safeReturnPath('/verification-required/')).toBe('/');
      expect(safeReturnPath('/access-denied')).toBe('/');
      expect(safeReturnPath('/access-denied?anything')).toBe('/');
      expect(safeReturnPath('/access-denied/')).toBe('/');
      expect(safeReturnPath('/access-pending')).toBe('/');
      expect(safeReturnPath('/access-pending?anything')).toBe('/');
      expect(safeReturnPath('/access-pending/')).toBe('/');

      // API routes
      expect(safeReturnPath('/api/auth/login')).toBe('/');
      expect(safeReturnPath('/api/auth/callback')).toBe('/');
    });

    it('rejects encoded traversal and bypass attempts', () => {
      expect(safeReturnPath('/auth%2fcallback')).toBe('/');
      expect(safeReturnPath('/%5cevil')).toBe('/');
      expect(safeReturnPath('/%2f/evil.example.com')).toBe('/');
    });

    it('handles null, undefined, empty, and non-string inputs safely', () => {
      expect(safeReturnPath('')).toBe('/');
      expect(safeReturnPath(null)).toBe('/');
      expect(safeReturnPath(undefined)).toBe('/');
      // @ts-expect-error test non-string type
      expect(safeReturnPath(123)).toBe('/');
    });
  });

  it('has no browser token-storage API', async () => {
    const browserAuth = await import('@/lib/auth');
    expect('storeTokens' in browserAuth).toBe(false);
    expect('getRefreshToken' in browserAuth).toBe(false);
    expect('getAccessToken' in browserAuth).toBe(false);
  });
});
