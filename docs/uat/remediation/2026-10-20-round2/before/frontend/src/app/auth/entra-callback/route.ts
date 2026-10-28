// A standalone bridge keeps auth guards and application scripts off the callback.
export function GET() {
  return new Response('<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Microsoft Authentication</title></head><body><p>Completing Microsoft sign-in…</p><script src="/api/auth/entra/bridge"></script></body></html>', {
    headers: {
      'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
      'Content-Security-Policy': "default-src 'none'; script-src 'self'; base-uri 'none'; frame-ancestors 'self'",
    },
  });
}
