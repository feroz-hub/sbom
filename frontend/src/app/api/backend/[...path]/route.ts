import { NextRequest, NextResponse } from 'next/server';
import { getDiscovery, refreshTokens } from '@/lib/auth/oidc';
import { serverAuthConfig } from '@/lib/auth/server-config';
import {
  destroySession, getSession, SESSION_COOKIE, setSession, singleFlightRefresh, type TokenSession,
} from '@/lib/auth/session-store';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

async function usableSession(id: string, force = false): Promise<TokenSession | null> {
  const current = getSession(id);
  if (!current) return null;
  if (!force && current.expiresAt > Date.now() + 60_000) return current;
  return singleFlightRefresh(id, async () => {
    const latest = getSession(id);
    if (!latest) return null;
    if (!force && latest.expiresAt > Date.now() + 60_000) return latest;
    const config = serverAuthConfig();
    const next = await refreshTokens(latest, config, await getDiscovery(config));
    if (next) setSession(id, next);
    else destroySession(id);
    return next;
  });
}

async function proxy(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  const config = serverAuthConfig();
  const id = request.cookies.get(SESSION_COOKIE)?.value;
  if (config.enabled && !id) return NextResponse.json({ detail: 'Authentication required' }, { status: 401 });
  let session = id ? await usableSession(id) : null;
  if (config.enabled && !session) return NextResponse.json({ detail: 'Authentication required' }, { status: 401 });

  const { path } = await context.params;
  const target = new URL(`/${path.join('/')}`, `${config.apiUrl}/`);
  target.search = request.nextUrl.search;
  const headers = new Headers(request.headers);
  for (const name of ['host', 'cookie', 'content-length', 'connection']) headers.delete(name);
  if (session) headers.set('Authorization', `Bearer ${session.accessToken}`);
  else headers.delete('Authorization');
  const body = ['GET', 'HEAD'].includes(request.method) ? undefined : await request.arrayBuffer();
  const send = () => fetch(target, { method: request.method, headers, body, redirect: 'manual', cache: 'no-store' });
  let upstream = await send();
  if (upstream.status === 401 && id && session) {
    session = await usableSession(id, true);
    if (session) {
      headers.set('Authorization', `Bearer ${session.accessToken}`);
      upstream = await send();
    }
  }
  if (!upstream.ok) {
    // Do not log query strings, headers, cookies, or token-bearing bodies.
    console.warn(`[api/backend] ${request.method} /${path.join('/')} -> ${upstream.status}`);
  }
  const responseHeaders = new Headers(upstream.headers);
  responseHeaders.delete('set-cookie');
  responseHeaders.delete('www-authenticate');
  // Node fetch transparently decodes compressed upstream bodies. Forwarding
  // the original encoding/length makes the browser try to decode them again,
  // which surfaces as a successful status with an unreadable response body.
  responseHeaders.delete('content-encoding');
  responseHeaders.delete('content-length');
  responseHeaders.delete('transfer-encoding');
  // Next.js development route handlers can close a proxied JSON stream before
  // the browser finishes reading it. Buffer structured API responses here;
  // binary downloads remain streamed to avoid loading large files into memory.
  const contentType = responseHeaders.get('content-type') || '';
  const responseBody = contentType.includes('json') ? await upstream.arrayBuffer() : upstream.body;
  return new NextResponse(responseBody, { status: upstream.status, headers: responseHeaders });
}

export const GET = proxy;
export const POST = proxy;
export const PUT = proxy;
export const PATCH = proxy;
export const DELETE = proxy;
