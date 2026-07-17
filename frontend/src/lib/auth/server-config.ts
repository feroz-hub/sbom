import 'server-only';

export interface ServerAuthConfig {
  enabled: boolean;
  issuer: string;
  clientId: string;
  redirectUri: string;
  postLogoutRedirectUri: string;
  scopes: string;
  apiUrl: string;
  caBundle: string;
}

export function serverAuthConfig(): ServerAuthConfig {
  const config = {
    enabled: process.env.NEXT_PUBLIC_AUTH_ENABLED === 'true',
    issuer: (process.env.NEXT_PUBLIC_HCL_IAM_ISSUER || '').replace(/\/$/, ''),
    clientId: process.env.NEXT_PUBLIC_HCL_IAM_CLIENT_ID || '',
    redirectUri: process.env.NEXT_PUBLIC_HCL_IAM_REDIRECT_URI || 'https://localhost:3000/auth/callback',
    postLogoutRedirectUri:
      process.env.NEXT_PUBLIC_HCL_IAM_POST_LOGOUT_REDIRECT_URI ||
      process.env.NEXT_PUBLIC_HCL_IAM_POST_LOGOUT_URI ||
      'https://localhost:3000',
    scopes: process.env.NEXT_PUBLIC_HCL_IAM_SCOPES || 'openid profile email offline_access sbom-analyser-api',
    apiUrl: (process.env.SBOM_API_URL || 'http://localhost:8000').replace(/\/$/, ''),
    caBundle: process.env.HCL_IAM_CA_BUNDLE || '',
  };
  if (config.enabled) {
    for (const [name, value] of Object.entries({ issuer: config.issuer, clientId: config.clientId })) {
      if (!value) throw new Error(`Missing OIDC configuration: ${name}`);
    }
    if (!config.issuer.startsWith('https://')) throw new Error('OIDC issuer must use HTTPS');
  }
  return config;
}
