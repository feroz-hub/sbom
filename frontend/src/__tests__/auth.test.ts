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
    expect(safeReturnPath('/projects?view=all')).toBe('/projects?view=all');
    expect(safeReturnPath('https://evil.example')).toBe('/');
    expect(safeReturnPath('//evil.example')).toBe('/');
  });

  it('has no browser token-storage API', async () => {
    const browserAuth = await import('@/lib/auth');
    expect('storeTokens' in browserAuth).toBe(false);
    expect('getRefreshToken' in browserAuth).toBe(false);
    expect('getAccessToken' in browserAuth).toBe(false);
  });
});
