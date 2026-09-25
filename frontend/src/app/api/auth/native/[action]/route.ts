import { NextRequest, NextResponse } from 'next/server';
import { trustedMutationOrigin } from '@/lib/auth/origin';
import { createSession, destroySession, SESSION_COOKIE } from '@/lib/auth/session-store';

export const runtime = 'nodejs';

export async function POST(request: NextRequest, context: { params: Promise<{ action: string }> }) {
  if (process.env.NATIVE_AUTH_ENABLED !== 'true') return NextResponse.json({ detail: 'Unavailable' }, { status: 404 });
  if (!trustedMutationOrigin(request)) return NextResponse.json({ detail: 'Untrusted origin' }, { status: 403 });
  const { action } = await context.params;
  if (!['login', 'activate'].includes(action)) return NextResponse.json({ detail: 'Not found' }, { status: 404 });
  try {
    const body = await request.text();
    if (body.length > 8192) return NextResponse.json({ detail: 'Request too large' }, { status: 413 });
    const upstream = await fetch(`${process.env.SBOM_API_URL || 'http://localhost:8000'}/api/auth/native/${action}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body, cache: 'no-store', redirect: 'error',
    });
    // Never forward validation input, tokens, or upstream diagnostics to the browser.
    if (!upstream.ok) return NextResponse.json({ detail: action === 'login' ? 'Invalid email or password' : 'Activation failed. Check the link and password requirements.' }, { status: upstream.status, headers: { 'Cache-Control': 'no-store' } });
    const response = NextResponse.json({ success: true }, { headers: { 'Cache-Control': 'no-store' } });
    if (action === 'login') {
      const data = await upstream.json();
      if (typeof data.access_token !== 'string' || !Number.isFinite(data.expires_in) || data.expires_in <= 0) throw new Error('Invalid response');
      const previous = request.cookies.get(SESSION_COOKIE)?.value;
      if (previous) destroySession(previous);
      const id = createSession({ provider: 'NATIVE', accessToken: data.access_token,
        expiresAt: Date.now() + data.expires_in * 1000, createdAt: Date.now() });
      response.cookies.set(SESSION_COOKIE, id, { httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: data.expires_in });
    }
    return response;
  } catch {
    return NextResponse.json({ detail: 'Authentication service unavailable' }, { status: 503 });
  }
}
