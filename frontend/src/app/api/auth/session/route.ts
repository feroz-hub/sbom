import { NextRequest, NextResponse } from 'next/server';
import { serverAuthConfig } from '@/lib/auth/server-config';
import { getSession, SESSION_COOKIE } from '@/lib/auth/session-store';

export const runtime = 'nodejs';

export async function GET(request: NextRequest) {
  const config = serverAuthConfig();
  if (!config.enabled) return NextResponse.json({ authenticated: true, development: true });
  const id = request.cookies.get(SESSION_COOKIE)?.value;
  const session = id ? getSession(id) : null;
  return NextResponse.json({ authenticated: Boolean(session && (session.provider !== 'NATIVE' || session.expiresAt > Date.now())) }, {
    headers: { 'Cache-Control': 'no-store' },
  });
}
