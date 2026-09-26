import { NextRequest, NextResponse } from 'next/server';
import { serverAuthConfig } from '@/lib/auth/server-config';
import { getSession, destroySession, SESSION_COOKIE } from '@/lib/auth/session-store';

export const runtime = 'nodejs';

export async function GET(request: NextRequest) {
  const config = serverAuthConfig();
  if (!config.enabled) return NextResponse.json({ authenticated: true, development: true });
  const id = request.cookies.get(SESSION_COOKIE)?.value;
  const session = id ? await getSession(id) : null;
  if (session?.provider === 'NATIVE') {
    try {
      const response = await fetch(`${config.apiUrl}/api/auth/native/session`, { headers: { Authorization: `Bearer ${session.accessToken}` }, cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(5000) });
      if (!response.ok) {
        if (response.status === 401 && id) await destroySession(id);
        return NextResponse.json({ authenticated: false }, { status: response.status === 401 ? 200 : 503, headers: { 'Cache-Control': 'no-store' } });
      }
    } catch { return NextResponse.json({ authenticated: false }, { status: 503 }); }
  }
  return NextResponse.json({ provider: session?.provider || 'HCL_CS', authenticated: Boolean(session && (session.provider !== 'NATIVE' || session.expiresAt > Date.now())) }, {
    headers: { 'Cache-Control': 'no-store' },
  });
}
