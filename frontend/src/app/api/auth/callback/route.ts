import { NextRequest, NextResponse } from 'next/server';
import { constantTimeEqual } from '@/lib/auth/pkce';
import { exchangeCode, getDiscovery } from '@/lib/auth/oidc';
import { serverAuthConfig } from '@/lib/auth/server-config';
import { consumeTransaction, createSession, LOGIN_COOKIE, SESSION_COOKIE } from '@/lib/auth/session-store';

export const runtime = 'nodejs';

export async function POST(request: NextRequest) {
  const transactionId = request.cookies.get(LOGIN_COOKIE)?.value;
  const transaction = transactionId ? consumeTransaction(transactionId) : null;
  const clearLogin = (response: NextResponse) => {
    response.cookies.set(LOGIN_COOKIE, '', { httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: 0 });
    return response;
  };
  try {
    const body = (await request.json()) as { code?: string; state?: string; error?: string };
    if (body.error || !body.code || !body.state || !transaction) {
      return clearLogin(NextResponse.json({ error: 'Authentication could not be completed.' }, { status: 400 }));
    }
    if (!constantTimeEqual(body.state, transaction.state)) {
      return clearLogin(NextResponse.json({ error: 'Authentication state is invalid.' }, { status: 400 }));
    }
    const config = serverAuthConfig();
    const discovery = await getDiscovery(config);
    const session = await exchangeCode(body.code, transaction.verifier, transaction.nonce, config, discovery);
    const sessionId = createSession(session);
    const response = NextResponse.json({ returnTo: transaction.returnTo });
    response.cookies.set(SESSION_COOKIE, sessionId, {
      httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: 24 * 60 * 60,
    });
    return clearLogin(response);
  } catch {
    return clearLogin(NextResponse.json({ error: 'Authentication could not be completed.' }, { status: 400 }));
  }
}
