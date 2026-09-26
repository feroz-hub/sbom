/** Secret-safe validation, invoked by server startup, never the browser. */
export function validateProductionAuth() {
  if (process.env.NODE_ENV !== 'production' || process.env.NATIVE_AUTH_ENABLED !== 'true') return;
  const errors: string[] = [];
  if (process.env.NEXT_PUBLIC_AUTH_ENABLED !== 'true') errors.push('frontend_authentication');
  if (process.env.AUTH_SESSION_STORE !== 'redis') errors.push('shared_session_store');
  const key = process.env.AUTH_SESSION_ENCRYPTION_KEY || '';
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(key) || Buffer.from(key, 'base64').length !== 32) errors.push('session_encryption');
  try { const url = new URL(process.env.AUTH_SESSION_REDIS_URL || ''); if (!['redis:', 'rediss:'].includes(url.protocol)) throw new Error(); } catch { errors.push('session_redis'); }
  try { const origin = new URL(process.env.APP_ORIGIN || ''); if (origin.protocol !== 'https:' || origin.username || origin.password || origin.search || origin.hash || origin.pathname !== '/') throw new Error(); } catch { errors.push('canonical_origin'); }
  if (errors.length) throw new Error(`Native BFF configuration invalid: ${errors.join(',')}`);
}
