import { readFileSync } from 'node:fs';
import { join } from 'node:path';

export const runtime = 'nodejs';

export function GET() {
  // Serve the installed MSAL bridge from our origin, without a third-party CDN.
  const source = readFileSync(join(process.cwd(), 'node_modules/@azure/msal-browser/lib/redirect-bridge/msal-redirect-bridge.min.js'), 'utf8');
  return new Response(`${source}\nmsalRedirectBridge.broadcastResponseToMainFrame().catch(() => { document.body.textContent = 'Sign-in could not complete. Close this window and try again.'; });`, {
    headers: { 'Content-Type': 'text/javascript; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' },
  });
}
