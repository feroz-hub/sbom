import { NextRequest, NextResponse } from 'next/server';
import { createPkce, randomBase64Url, safeReturnPath } from '@/lib/auth/pkce';
import { getDiscovery } from '@/lib/auth/oidc';
import { serverAuthConfig } from '@/lib/auth/server-config';
import { createTransaction, LOGIN_COOKIE } from '@/lib/auth/session-store';

export const runtime = 'nodejs';

export async function GET(request: NextRequest) {
  try {
    const config = serverAuthConfig();
    if (!config.enabled) return NextResponse.redirect(new URL('/', request.url));
    const discovery = await getDiscovery(config);
    const { verifier, challenge } = createPkce();
    const state = randomBase64Url();
    const nonce = randomBase64Url();
    const transactionId = createTransaction({
      verifier, state, nonce,
      returnTo: safeReturnPath(request.nextUrl.searchParams.get('returnTo')),
      expiresAt: Date.now() + 10 * 60_000,
    });
    const authorization = new URL(discovery.authorization_endpoint);
    authorization.search = new URLSearchParams({
      response_type: 'code', client_id: config.clientId, redirect_uri: config.redirectUri,
      scope: config.scopes, code_challenge: challenge, code_challenge_method: 'S256', state, nonce,
    }).toString();
    const response = NextResponse.redirect(authorization);
    response.cookies.set(LOGIN_COOKIE, transactionId, {
      httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: 10 * 60,
    });
    return response;
  } catch (error) {
    const cause = error instanceof Error ? (error as Error & { cause?: { code?: string } }).cause : undefined;
    console.error(
      'OIDC login initialization failed:',
      error instanceof Error ? error.message : 'unknown error',
      cause?.code || '',
    );
    return NextResponse.redirect(new URL('/auth/callback?error=configuration_error', request.url));
  }
}
