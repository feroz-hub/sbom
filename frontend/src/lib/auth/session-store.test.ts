import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

vi.mock('server-only', () => ({}));

let tempDir: string;
let sessionStore: typeof import('./session-store');

beforeAll(async () => {
  tempDir = mkdtempSync(join(tmpdir(), 'sbom-auth-test-'));
  const keyFile = join(tempDir, 'transaction.key');
  writeFileSync(keyFile, 'unit-test-only-transaction-key');
  process.env.AUTH_TRANSACTION_KEY_FILE = keyFile;
  sessionStore = await import('./session-store');
});

afterAll(() => {
  delete process.env.AUTH_TRANSACTION_KEY_FILE;
  rmSync(tempDir, { recursive: true, force: true });
});

describe('sealed login transactions', () => {
  it('round-trips an unexpired transaction', () => {
    const transaction = {
      verifier: 'verifier',
      state: 'state',
      nonce: 'nonce',
      returnTo: '/projects',
      expiresAt: Date.now() + 60_000,
    };

    const sealed = sessionStore.createTransaction(transaction);

    expect(sealed).not.toContain(transaction.verifier);
    expect(sessionStore.consumeTransaction(sealed)).toEqual(transaction);
  });

  it('rejects tampered and expired transactions', () => {
    const sealed = sessionStore.createTransaction({
      verifier: 'verifier', state: 'state', nonce: 'nonce', returnTo: '/', expiresAt: Date.now() + 60_000,
    });
    const tampered = `${sealed.slice(0, -1)}${sealed.endsWith('A') ? 'B' : 'A'}`;
    const expired = sessionStore.createTransaction({
      verifier: 'verifier', state: 'state', nonce: 'nonce', returnTo: '/', expiresAt: Date.now() - 1,
    });

    expect(sessionStore.consumeTransaction(tampered)).toBeNull();
    expect(sessionStore.consumeTransaction(expired)).toBeNull();
  });
});

it('refuses process-memory sessions in production', async () => {
  vi.stubEnv('NODE_ENV', 'production'); vi.stubEnv('AUTH_SESSION_STORE', 'memory');
  try { await expect(sessionStore.getSession('any')).rejects.toThrow('Production requires shared sessions'); }
  finally { vi.unstubAllEnvs(); }
});

it('creates opaque native sessions, expires them, and supports idempotent logout', async () => {
  const session = { provider: 'NATIVE' as const, accessToken: 'server-side-only', expiresAt: Date.now()+60000, createdAt: Date.now() };
  const id = await sessionStore.createSession(session);
  expect(id).not.toContain('server-side-only'); expect(await sessionStore.getSession(id)).toEqual(session);
  await sessionStore.destroySession(id); await sessionStore.destroySession(id);
  expect(await sessionStore.getSession(id)).toBeNull();
  const expired = await sessionStore.createSession({ ...session, expiresAt: Date.now()-1 });
  expect(await sessionStore.getSession(expired)).toBeNull();
});
