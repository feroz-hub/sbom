import { NextRequest, NextResponse } from 'next/server';
import { getDiscovery, revokeToken } from '@/lib/auth/oidc';
import { serverAuthConfig } from '@/lib/auth/server-config';
import { destroySession, getSession, SESSION_COOKIE } from '@/lib/auth/session-store';

export const runtime = 'nodejs';

export async function POST(request: NextRequest) {
  const config = serverAuthConfig();
  const id = request.cookies.get(SESSION_COOKIE)?.value;
  const session = id ? getSession(id) : null;
  let redirectUrl = config.postLogoutRedirectUri;
  try {
    const discovery = await getDiscovery(config);
    if (session && discovery.revocation_endpoint) {
      for (const token of [session.refreshToken, session.accessToken]) {
        if (!token) continue;
        await revokeToken(token, config, discovery).catch(() => undefined);
      }
    }
    if (discovery.end_session_endpoint) {
      const endSession = new URL(discovery.end_session_endpoint);
      endSession.searchParams.set('post_logout_redirect_uri', config.postLogoutRedirectUri);
      if (session?.idToken) endSession.searchParams.set('id_token_hint', session.idToken);
      redirectUrl = endSession.toString();
    }
  } catch {
    // Local session deletion remains authoritative if the provider is down.
  }
  if (id) destroySession(id);
  const response = NextResponse.json({ redirectUrl });
  response.cookies.set(SESSION_COOKIE, '', { httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: 0 });
  return response;
}
