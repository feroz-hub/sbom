import { NextRequest, NextResponse } from 'next/server';

export function proxy(request: NextRequest) {
  if (process.env.NEXT_PUBLIC_AUTH_ENABLED !== 'true') return NextResponse.next();
  if (request.cookies.has('__Host-sbom-session')) return NextResponse.next();
  const returnTo = `${request.nextUrl.pathname}${request.nextUrl.search}`;
  const login = new URL('/api/auth/login', request.url);
  login.searchParams.set('returnTo', returnTo);
  return NextResponse.redirect(login);
}

export const config = {
  matcher: ['/((?!api|auth/callback|access-denied|_next/static|_next/image|favicon.ico).*)'],
};
