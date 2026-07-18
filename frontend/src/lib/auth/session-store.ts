import 'server-only';
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { randomBase64Url } from './pkce';

export const SESSION_COOKIE = '__Host-sbom-session';
export const LOGIN_COOKIE = '__Host-sbom-login';

export interface LoginTransaction {
  verifier: string;
  state: string;
  nonce: string;
  returnTo: string;
  expiresAt: number;
}

export interface TokenSession {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  expiresAt: number;
  createdAt: number;
}

interface StoreState {
  sessions: Map<string, TokenSession>;
  refreshes: Map<string, Promise<TokenSession | null>>;
}

const globalStore = globalThis as typeof globalThis & { __sbomAuthStore?: StoreState };
const store = globalStore.__sbomAuthStore ?? {
  sessions: new Map(),
  refreshes: new Map(),
};
globalStore.__sbomAuthStore = store;

let cachedTransactionKey: Buffer | null = null;

function transactionKey(): Buffer {
  if (cachedTransactionKey) return cachedTransactionKey;
  const configured = process.env.AUTH_TRANSACTION_KEY_FILE;
  const keyFile = configured ? resolve(configured) : resolve(process.cwd(), 'certificates/localhost-key.pem');
  cachedTransactionKey = createHash('sha256').update(readFileSync(keyFile)).digest();
  return cachedTransactionKey;
}

function prune(): void {
  const now = Date.now();
  for (const [key, session] of store.sessions) {
    if (session.expiresAt + 24 * 60 * 60 * 1000 <= now) store.sessions.delete(key);
  }
}

export function createTransaction(value: LoginTransaction): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', transactionKey(), iv);
  const plaintext = Buffer.from(JSON.stringify({ version: 1, ...value }), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return [iv, ciphertext, cipher.getAuthTag()].map((part) => part.toString('base64url')).join('.');
}

export function consumeTransaction(value: string): LoginTransaction | null {
  try {
    const parts = value.split('.');
    if (parts.length !== 3) return null;
    const decodedParts = parts.map((part) => Buffer.from(part, 'base64url'));
    // Reject alternate/non-canonical base64url spellings. Without this,
    // changing unused trailing bits can leave the decoded authenticated
    // bytes unchanged and make a visibly modified cookie appear valid.
    if (decodedParts.some((part, index) => part.toString('base64url') !== parts[index])) return null;
    const [iv, ciphertext, tag] = decodedParts;
    const decipher = createDecipheriv('aes-256-gcm', transactionKey(), iv);
    decipher.setAuthTag(tag);
    const decoded = JSON.parse(
      Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8'),
    ) as Partial<LoginTransaction> & { version?: number };
    if (
      decoded.version !== 1 ||
      typeof decoded.verifier !== 'string' ||
      typeof decoded.state !== 'string' ||
      typeof decoded.nonce !== 'string' ||
      typeof decoded.returnTo !== 'string' ||
      typeof decoded.expiresAt !== 'number' ||
      decoded.expiresAt <= Date.now()
    ) return null;
    return {
      verifier: decoded.verifier,
      state: decoded.state,
      nonce: decoded.nonce,
      returnTo: decoded.returnTo,
      expiresAt: decoded.expiresAt,
    };
  } catch {
    return null;
  }
}

export function createSession(value: TokenSession): string {
  prune();
  const id = randomBase64Url();
  store.sessions.set(id, value);
  return id;
}

export function getSession(id: string): TokenSession | null {
  return store.sessions.get(id) ?? null;
}

export function setSession(id: string, value: TokenSession): void {
  store.sessions.set(id, value);
}

export function destroySession(id: string): void {
  store.sessions.delete(id);
  store.refreshes.delete(id);
}

export async function singleFlightRefresh(
  id: string,
  refresh: () => Promise<TokenSession | null>,
): Promise<TokenSession | null> {
  const existing = store.refreshes.get(id);
  if (existing) return existing;
  const pending = refresh().finally(() => store.refreshes.delete(id));
  store.refreshes.set(id, pending);
  return pending;
}
