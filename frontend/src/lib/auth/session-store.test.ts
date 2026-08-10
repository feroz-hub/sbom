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
