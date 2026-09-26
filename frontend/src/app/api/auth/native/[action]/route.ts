import { NextRequest, NextResponse } from 'next/server';
import { trustedMutationOrigin } from '@/lib/auth/origin';
import { createSession, destroySession, getSession, SESSION_COOKIE } from '@/lib/auth/session-store';

export const runtime = 'nodejs';

export async function POST(request: NextRequest, context: { params: Promise<{ action: string }> }) {
  if (process.env.NATIVE_AUTH_ENABLED !== 'true') return NextResponse.json({ detail: 'Unavailable' }, { status: 404 });
  if (!trustedMutationOrigin(request)) return NextResponse.json({ detail: 'Untrusted origin' }, { status: 403 });
  const { action } = await context.params;
  if (!['login', 'activate', 'forgot-password', 'reset-password', 'change-password', 'force-change-password', 'logout-all'].includes(action)) return NextResponse.json({ detail: 'Not found' }, { status: 404 });
  try {
    const body = await request.text();
    if (body.length > 8192) return NextResponse.json({ detail: 'Request too large' }, { status: 413 });
    const previous = request.cookies.get(SESSION_COOKIE)?.value;
    const session = previous ? await getSession(previous) : null;
    if (['change-password', 'logout-all'].includes(action) && session?.provider !== 'NATIVE') return NextResponse.json({ detail: 'Native authentication required' }, { status: 401 });
    const upstream = await fetch(`${process.env.SBOM_API_URL || 'http://localhost:8000'}/api/auth/native/${action}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', ...(session?.provider === 'NATIVE' ? { Authorization: `Bearer ${session.accessToken}` } : {}) }, body, cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(15000),
    });
    // Never forward validation input, tokens, or upstream diagnostics to the browser.
    if (!upstream.ok) return NextResponse.json({ detail: action === 'login' ? 'Invalid email or password' : 'Password operation failed. Check your credential, link, and password requirements.' }, { status: upstream.status, headers: { 'Cache-Control': 'no-store' } });
    const response = NextResponse.json({ success: true }, { headers: { 'Cache-Control': 'no-store' } });
    if (action === 'login') {
      const data = await upstream.json();
      if (data.password_change_required === true) {
        if (previous) await destroySession(previous);
        const restricted = NextResponse.json({ password_change_required: true }, { headers: { 'Cache-Control': 'no-store' } });
        restricted.cookies.set(SESSION_COOKIE, '', { httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: 0 });
        return restricted;
      }
      if (typeof data.access_token !== 'string' || !Number.isFinite(data.expires_in) || data.expires_in <= 0) throw new Error('Invalid response');
      if (previous) await destroySession(previous);
      const id = await createSession({ provider: 'NATIVE', accessToken: data.access_token,
        expiresAt: Date.now() + data.expires_in * 1000, createdAt: Date.now() });
      response.cookies.set(SESSION_COOKIE, id, { httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: data.expires_in });
    }
    if (['reset-password', 'change-password', 'force-change-password', 'logout-all'].includes(action)) {
      if (previous) await destroySession(previous);
      response.cookies.set(SESSION_COOKIE, '', { httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: 0 });
    }
    return response;
  } catch {
    return NextResponse.json({ detail: 'Authentication service unavailable' }, { status: 503 });
  }
}
