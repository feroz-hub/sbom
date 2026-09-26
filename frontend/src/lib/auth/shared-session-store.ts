import 'server-only';
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { createClient } from 'redis';
import type { TokenSession } from './session-store';

export interface SessionStore {
  get(id: string): Promise<TokenSession | null>;
  put(id: string, value: TokenSession, onlyExisting?: boolean): Promise<void>;
  delete(id: string): Promise<void>;
}

export class MemorySessionStore implements SessionStore {
  private values = new Map<string, TokenSession>();
  async get(id: string) {
    const value = this.values.get(id);
    if (value && retention(value) > Date.now()) return value;
    this.values.delete(id); return null;
  }
  async put(id: string, value: TokenSession, onlyExisting = false) {
    for (const [key, entry] of this.values) if (retention(entry) <= Date.now()) this.values.delete(key);
    if (!onlyExisting || this.values.has(id)) this.values.set(id, value);
  }
  async delete(id: string) { this.values.delete(id); }
}
function retention(value: TokenSession) {
  return value.expiresAt + (value.provider === 'NATIVE' ? 0 : 86_400_000);
}
export class RedisSessionStore implements SessionStore {
  constructor(private client: ReturnType<typeof createClient>, private key: Buffer, private prefix = 'sbom:bff:') {
    if (key.length !== 32) throw new Error('Session encryption requires a 32-byte key');
  }
  private name(id: string) { return `${this.prefix}${createHash('sha256').update(id).digest('hex')}`; }
  async ready() { return this.client.isReady && await this.client.ping() === "PONG"; }
  async get(id: string) {
    if (!this.client.isReady) throw new Error("Session store unavailable");
    const raw = await this.client.get(this.name(id));
    if (!raw) return null;
    try {
      const [iv, data, tag] = raw.split('.').map(s => Buffer.from(s, 'base64url'));
      const decipher = createDecipheriv('aes-256-gcm', this.key, iv);
      decipher.setAAD(Buffer.from(this.name(id))); decipher.setAuthTag(tag);
      const value = JSON.parse(Buffer.concat([decipher.update(data), decipher.final()]).toString()) as TokenSession;
      if (typeof value.accessToken !== 'string' || !Number.isFinite(value.expiresAt) || retention(value) <= Date.now()) return null;
      return value;
    } catch { return null; }
  }
  async put(id: string, value: TokenSession, onlyExisting = false) {
    if (!this.client.isReady) throw new Error("Session store unavailable");
    const iv = randomBytes(12); const cipher = createCipheriv('aes-256-gcm', this.key, iv);
    cipher.setAAD(Buffer.from(this.name(id)));
    const encrypted = Buffer.concat([cipher.update(JSON.stringify(value)), cipher.final()]);
    const raw = [iv, encrypted, cipher.getAuthTag()].map(b => b.toString('base64url')).join('.');
    const ttl = Math.max(1, Math.ceil((retention(value) - Date.now()) / 1000));
    // XX prevents an in-flight refresh resurrecting a logged-out session.
    await this.client.set(this.name(id), raw, { EX: ttl, ...(onlyExisting ? { XX: true } : {}) });
  }
  async delete(id: string) { await this.client.del(this.name(id)); }
  async refresh(id: string, operation: () => Promise<TokenSession | null>): Promise<TokenSession | null> {
    const lock = `${this.name(id)}:refresh`;
    const owner = randomBytes(24).toString('hex');
    if (await this.client.set(lock, owner, { NX: true, PX: 30_000 })) {
      try { return await operation(); }
      finally { await this.client.eval("if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end", { keys: [lock], arguments: [owner] }); }
    }
    // Another replica owns the refresh. Never reuse the old refresh credential.
    for (let i = 0; i < 100; i++) {
      await new Promise(resolve => setTimeout(resolve, 100));
      if (!await this.client.exists(lock)) return this.get(id);
    }
    throw new Error('Session refresh unavailable');
  }
}
export const redisReconnectDelay = (retries: number) => retries < 8 ? Math.min(2000, 100 * 2 ** retries) : false;
let redisStore: Promise<RedisSessionStore> | undefined;
export async function configuredRedisStore() {
  if (!redisStore) redisStore = (async () => {
    const url = process.env.AUTH_SESSION_REDIS_URL;
    const key = Buffer.from(process.env.AUTH_SESSION_ENCRYPTION_KEY || '', 'base64');
    if (!url || key.length !== 32) throw new Error('Shared session store is not configured');
    const client = createClient({ url, disableOfflineQueue: true, socket: { connectTimeout: 5000, reconnectStrategy: redisReconnectDelay } });
    client.on('end', () => { redisStore = undefined; });
    client.on('error', () => { /* Never log URLs, tokens or Redis diagnostics. */ });
    await client.connect();
    return new RedisSessionStore(client, key);
  })().catch(error => { redisStore = undefined; throw error; });
  return redisStore;
}
