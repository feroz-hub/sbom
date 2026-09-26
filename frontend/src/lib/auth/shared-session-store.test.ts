import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { createClient } from 'redis';
import { beforeAll, afterAll, describe, expect, it, vi } from 'vitest';
vi.mock('server-only', () => ({}));
import { RedisSessionStore, MemorySessionStore } from './shared-session-store';
let process: ChildProcess;
let directory: string;
let a: ReturnType<typeof createClient>;
let b: ReturnType<typeof createClient>;
let first: RedisSessionStore;
let second: RedisSessionStore;
beforeAll(async () => {
  directory = mkdtempSync(join(tmpdir(), 'sbom-session-test-'));
  const socket = join(directory, 'redis.sock');
  process = spawn('redis-server', ['--port', '0', '--unixsocket', socket, '--save', '', '--appendonly', 'no'], { stdio: 'ignore' });
  for (let i = 0; i < 100 && !existsSync(socket); i++) await new Promise(resolve => setTimeout(resolve, 30));
  a = createClient({ socket: { path: socket, reconnectStrategy: false } });
  b = createClient({ socket: { path: socket, reconnectStrategy: false } });
  a.on('error', () => {}); b.on('error', () => {});
  await a.connect(); await b.connect();
  const key = randomBytes(32);
  first = new RedisSessionStore(a, key); second = new RedisSessionStore(b, key);
});
afterAll(async () => {
  if (a?.isOpen) await a.quit(); if (b?.isOpen) await b.quit();
  if (process && process.exitCode === null) { const stopped = new Promise(resolve => process.once('exit', resolve)); process.kill('SIGTERM'); await stopped; }
  if (directory) rmSync(directory, { recursive: true, force: true });
});
const session = () => ({ provider: 'NATIVE' as const, accessToken: 'private-jwt', expiresAt: Date.now() + 60_000, createdAt: Date.now() });
describe('two replicas sharing encrypted Redis sessions', () => {
  it('reads across instances without storing bearer/session secrets as plaintext', async () => {
    const value = session(); await first.put('opaque-secret', value);
    expect(await second.get('opaque-secret')).toEqual(value);
    const keys = await a.keys('sbom:bff:*');
    expect(keys.join()).not.toContain('opaque-secret');
    const raw = await a.get(keys[0]); expect(raw).not.toContain('private-jwt');
    await second.delete('opaque-secret'); expect(await first.get('opaque-secret')).toBeNull();
    await second.delete('opaque-secret');
  });
  it('expires native sessions', async () => {
    await first.put('expired', { ...session(), expiresAt: Date.now() - 1 });
    expect(await second.get('expired')).toBeNull();
  });
  it('serializes refreshes across replicas', async () => {
    await first.put('hcl', { ...session(), provider: 'HCL_CS' });
    let calls = 0;
    const refresh = async () => { calls++; await new Promise(resolve => setTimeout(resolve, 150)); const next = { ...session(), provider: 'HCL_CS' as const, accessToken: 'new-hcl-token' }; await first.put('hcl', next, true); return next; };
    const values = await Promise.all([first.refresh('hcl', refresh), second.refresh('hcl', refresh)]);
    expect(calls).toBe(1); expect(values.map(v => v?.accessToken)).toEqual(['new-hcl-token','new-hcl-token']);
  });
  it('does not resurrect logout during refresh', async () => {
    await first.put('race', session()); await second.delete('race');
    await first.put('race', session(), true); expect(await second.get('race')).toBeNull();
  });
  it('rejects corrupt ciphertext', async () => {
    await a.flushDb(); await first.put('tampered', session());
    const [key] = await a.keys('sbom:bff:*'); await a.set(key, 'bad.cipher.text');
    expect(await second.get('tampered')).toBeNull();
  });
  it('memory fallback is development-only and honors expiry', async () => {
    const memory = new MemorySessionStore(); await memory.put('dev', session()); expect(await memory.get('dev')).not.toBeNull();
    await memory.delete('dev'); expect(await memory.get('dev')).toBeNull();
    await memory.put('expired', { ...session(), expiresAt: Date.now()-1 }); expect(await memory.get('expired')).toBeNull();
  });
});
