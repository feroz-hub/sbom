import 'server-only';
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
  transactions: Map<string, LoginTransaction>;
  refreshes: Map<string, Promise<TokenSession | null>>;
}

const globalStore = globalThis as typeof globalThis & { __sbomAuthStore?: StoreState };
const store = globalStore.__sbomAuthStore ?? {
  sessions: new Map(),
  transactions: new Map(),
  refreshes: new Map(),
};
globalStore.__sbomAuthStore = store;

function prune(): void {
  const now = Date.now();
  for (const [key, tx] of store.transactions) if (tx.expiresAt <= now) store.transactions.delete(key);
  for (const [key, session] of store.sessions) {
    if (session.expiresAt + 24 * 60 * 60 * 1000 <= now) store.sessions.delete(key);
  }
}

export function createTransaction(value: LoginTransaction): string {
  prune();
  const id = randomBase64Url();
  store.transactions.set(id, value);
  return id;
}

export function consumeTransaction(id: string): LoginTransaction | null {
  const value = store.transactions.get(id) ?? null;
  store.transactions.delete(id);
  return value && value.expiresAt > Date.now() ? value : null;
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
