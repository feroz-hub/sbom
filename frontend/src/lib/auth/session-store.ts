import 'server-only';
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { randomBase64Url } from './pkce';
import { configuredRedisStore, MemorySessionStore, type SessionStore } from './shared-session-store';

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
  provider?: 'HCL_CS' | 'NATIVE';
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  expiresAt: number;
  createdAt: number;
}

interface StoreState {
  sessions: SessionStore;
  refreshes: Map<string, Promise<TokenSession | null>>;
}

const globalStore = globalThis as typeof globalThis & { __sbomAuthStore?: StoreState };
const store = globalStore.__sbomAuthStore ?? {
  sessions: new MemorySessionStore(),
  refreshes: new Map(),
};
globalStore.__sbomAuthStore = store;

let cachedTransactionKey: Buffer | null = null;

function transactionKey(): Buffer {
  if (cachedTransactionKey) return cachedTransactionKey;
  const configured = process.env.AUTH_TRANSACTION_KEY_FILE;
  // Both paths are runtime inputs. In production the key is mounted under
  // /run/secrets; excluding it from output tracing prevents build-host key
  // material from being copied into standalone output.
  const keyFile = configured
    ? resolve(/* turbopackIgnore: true */ configured)
    : resolve(/* turbopackIgnore: true */ process.cwd(), 'certificates/localhost-key.pem');
  cachedTransactionKey = createHash('sha256').update(readFileSync(keyFile)).digest();
  return cachedTransactionKey;
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

export async function createSession(value: TokenSession): Promise<string> {
  const id = randomBase64Url();
  if (shared()) await (await configuredRedisStore()).put(id, value);
  else await store.sessions.put(id, value);
  return id;
}

function shared(): boolean {
  if (process.env.AUTH_SESSION_STORE === 'redis') return true;
  if (process.env.NODE_ENV === 'production') throw new Error('Production requires shared sessions');
  return false;
}
export async function getSession(id: string): Promise<TokenSession | null> {
  if (shared()) return (await configuredRedisStore()).get(id);
  return store.sessions.get(id);
}

export async function setSession(id: string, value: TokenSession): Promise<void> {
  if (shared()) { await (await configuredRedisStore()).put(id, value, true); return; }
  await store.sessions.put(id, value, true);
}

export async function destroySession(id: string): Promise<void> {
  if (shared()) await (await configuredRedisStore()).delete(id);
  else await store.sessions.delete(id);
  store.refreshes.delete(id);
}

export async function singleFlightRefresh(
  id: string,
  refresh: () => Promise<TokenSession | null>,
): Promise<TokenSession | null> {
  if (shared()) return (await configuredRedisStore()).refresh(id, refresh);
  const existing = store.refreshes.get(id);
  if (existing) return existing;
  const pending = refresh().finally(() => store.refreshes.delete(id));
  store.refreshes.set(id, pending);
  return pending;
}
