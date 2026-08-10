import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

export function randomBase64Url(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

export function createPkce(): { verifier: string; challenge: string } {
  const verifier = randomBase64Url(64);
  const challenge = createHash('sha256').update(verifier, 'ascii').digest('base64url');
  return { verifier, challenge };
}

export function constantTimeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

export function safeReturnPath(value: string | null | undefined): string {
  if (!value || !value.startsWith('/') || value.startsWith('//') || value.includes('\\')) return '/';
  return value;
}
