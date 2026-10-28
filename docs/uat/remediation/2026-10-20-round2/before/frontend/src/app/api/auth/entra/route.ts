import { NextRequest, NextResponse } from 'next/server';
import { entraConfig } from '@/lib/auth/entra-config';
import { trustedMutationOrigin } from '@/lib/auth/origin';
import { createSession, destroySession, SESSION_COOKIE } from '@/lib/auth/session-store';

export const runtime = 'nodejs';
const headers = { 'Cache-Control': 'no-store' };

export async function GET() {
  try {
    const config = entraConfig();
    return NextResponse.json(config ? { enabled: true, ...config } : { enabled: false }, { headers });
  } catch {
    return NextResponse.json({ detail: 'Microsoft sign-in unavailable' }, { status: 503, headers });
  }
}

export async function POST(request: NextRequest) {
  if (!trustedMutationOrigin(request)) return NextResponse.json({ detail: 'Untrusted origin' }, { status: 403, headers });
  try {
    if (!entraConfig()) return NextResponse.json({ detail: 'Unavailable' }, { status: 404, headers });
    const body = await request.text();
    if (body.length > 32768) return NextResponse.json({ detail: 'Request too large' }, { status: 413, headers });
    const { accessToken } = JSON.parse(body);
    if (typeof accessToken !== 'string' || !accessToken || /\s/.test(accessToken)) return NextResponse.json({ detail: 'Invalid token' }, { status: 400, headers });
    const upstream = await fetch(`${process.env.SBOM_API_URL || 'http://localhost:8000'}/api/auth/entra/session`, {
      headers: { Authorization: `Bearer ${accessToken}` }, cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    if (!upstream.ok) return NextResponse.json({ detail: 'Microsoft sign-in could not be validated' }, { status: upstream.status === 401 ? 401 : 503, headers });
    const data = await upstream.json();
    if (data.provider !== 'MICROSOFT_ENTRA' || !Number.isFinite(data.expires_at) || data.expires_at * 1000 <= Date.now()) throw new Error();
    // Status is checked again by the API on every request, including pending sessions.
    const previous = request.cookies.get(SESSION_COOKIE)?.value;
    if (previous) await destroySession(previous);
    const id = await createSession({ provider: 'MICROSOFT_ENTRA', accessToken, expiresAt: data.expires_at * 1000, createdAt: Date.now() });
    const response = NextResponse.json({ status: data.status }, { headers });
    response.cookies.set(SESSION_COOKIE, id, { httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: Math.floor(data.expires_at - Date.now() / 1000) });
    return response;
  } catch {
    return NextResponse.json({ detail: 'Microsoft sign-in unavailable' }, { status: 503, headers });
  }
}
