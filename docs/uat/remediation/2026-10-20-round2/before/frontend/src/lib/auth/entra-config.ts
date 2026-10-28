import 'server-only';

export function entraConfig() {
  if (process.env.ENTRA_ENABLED !== 'true') return null;
  const tenantId = process.env.ENTRA_TENANT_ID || '';
  const clientId = process.env.ENTRA_FRONTEND_CLIENT_ID || '';
  const apiClientId = process.env.ENTRA_API_CLIENT_ID || '';
  const scope = process.env.ENTRA_API_SCOPE || '';
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  try {
    const origin = new URL(process.env.APP_ORIGIN || '');
    const scopeUrl = new URL(scope);
    if (![tenantId, clientId, apiClientId].every(value => uuid.test(value)) || clientId === apiClientId
      || process.env.NEXT_PUBLIC_AUTH_ENABLED !== 'true'
      || origin.protocol !== 'https:' || origin.username || origin.password || origin.search || origin.hash || origin.pathname !== '/'
      || !['api:', 'https:'].includes(scopeUrl.protocol) || !scopeUrl.host || !scopeUrl.pathname.slice(1)
      || scopeUrl.pathname.endsWith('/.default') || scopeUrl.search || scopeUrl.hash || scopeUrl.username || scopeUrl.password || /\s/.test(scope)) throw new Error();
    return { tenantId, clientId, scope, authority: `https://login.microsoftonline.com/${tenantId}`, redirectUri: `${origin.origin}/auth/entra-callback` };
  } catch {
    throw new Error('Microsoft Entra configuration invalid; check ENTRA settings and HTTPS APP_ORIGIN');
  }
}
