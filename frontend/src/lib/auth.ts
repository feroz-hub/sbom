/**
 * OIDC Authorization Code with PKCE — HCL IAM integration.
 *
 * Pure browser implementation (no external OIDC library). Uses the Web
 * Crypto API for SHA-256 code challenge generation and sessionStorage
 * for tab-isolated token/state storage.
 *
 * Key design decisions:
 *   - sessionStorage (not localStorage): each tab gets its own session,
 *     closing the tab clears the token automatically.
 *   - PKCE: S256 code challenge method — required for public clients.
 *   - No refresh token stored in browser: refresh is handled via silent
 *     re-auth or HCL IAM session if the IdP supports it.
 */

// ─── Auth configuration from env ────────────────────────────────────────────

export interface AuthConfig {
  /** Whether auth is enabled. When false, the app skips login. */
  enabled: boolean;
  /** OIDC issuer (e.g. https://iam.hcl.example.com/realms/sbom). */
  issuer: string;
  /** OIDC client ID (public client). */
  clientId: string;
  /** Post-login redirect URI (e.g. http://localhost:3000/auth/callback). */
  redirectUri: string;
  /** Post-logout redirect URI (e.g. http://localhost:3000). */
  postLogoutRedirectUri: string;
  /** Scopes to request. */
  scopes: string;
}

export function resolveAuthConfig(): AuthConfig {
  const enabled = process.env.NEXT_PUBLIC_AUTH_ENABLED === 'true';
  return {
    enabled,
    issuer: process.env.NEXT_PUBLIC_HCL_IAM_ISSUER || '',
    clientId: process.env.NEXT_PUBLIC_HCL_IAM_CLIENT_ID || '',
    redirectUri:
      process.env.NEXT_PUBLIC_HCL_IAM_REDIRECT_URI ||
      (typeof window !== 'undefined'
        ? `${window.location.origin}/auth/callback`
        : 'http://localhost:3000/auth/callback'),
    postLogoutRedirectUri:
      process.env.NEXT_PUBLIC_HCL_IAM_POST_LOGOUT_URI ||
      (typeof window !== 'undefined' ? window.location.origin : 'http://localhost:3000'),
    scopes: process.env.NEXT_PUBLIC_HCL_IAM_SCOPES || 'openid profile email',
  };
}

// ─── PKCE helpers ────────────────────────────────────────────────────────────

function base64urlEncode(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Generate a cryptographic random code verifier (43-128 chars, RFC 7636 §4.1). */
export function generateCodeVerifier(): string {
  const buffer = new Uint8Array(32);
  crypto.getRandomValues(buffer);
  return base64urlEncode(buffer.buffer);
}

/** Compute the S256 code challenge from a verifier (RFC 7636 §4.2). */
export async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return base64urlEncode(digest);
}

/** Generate a random state parameter for CSRF protection. */
export function generateState(): string {
  const buffer = new Uint8Array(16);
  crypto.getRandomValues(buffer);
  return base64urlEncode(buffer.buffer);
}

// ─── OIDC endpoint derivation ────────────────────────────────────────────────

/** Derive standard OIDC endpoints from the issuer URL. */
export function oidcEndpoints(issuer: string) {
  const base = issuer.replace(/\/$/, '');
  return {
    authorization: `${base}/protocol/openid-connect/auth`,
    token: `${base}/protocol/openid-connect/token`,
    logout: `${base}/protocol/openid-connect/logout`,
    userinfo: `${base}/protocol/openid-connect/userinfo`,
    wellKnown: `${base}/.well-known/openid-configuration`,
  };
}

// ─── Token storage (sessionStorage) ──────────────────────────────────────────

const STORAGE_KEYS = {
  accessToken: 'sbom_access_token',
  idToken: 'sbom_id_token',
  refreshToken: 'sbom_refresh_token',
  tokenExpiry: 'sbom_token_expiry',
  codeVerifier: 'sbom_code_verifier',
  authState: 'sbom_auth_state',
  returnUrl: 'sbom_return_url',
  activeTenantId: 'sbom_active_tenant_id',
} as const;

export function storeTokens(tokens: {
  access_token: string;
  id_token?: string;
  refresh_token?: string;
  expires_in?: number;
}): void {
  sessionStorage.setItem(STORAGE_KEYS.accessToken, tokens.access_token);
  if (tokens.id_token) {
    sessionStorage.setItem(STORAGE_KEYS.idToken, tokens.id_token);
  }
  if (tokens.refresh_token) {
    sessionStorage.setItem(STORAGE_KEYS.refreshToken, tokens.refresh_token);
  }
  if (tokens.expires_in) {
    const expiry = Date.now() + tokens.expires_in * 1000;
    sessionStorage.setItem(STORAGE_KEYS.tokenExpiry, String(expiry));
  }
}

export function getAccessToken(): string | null {
  return sessionStorage.getItem(STORAGE_KEYS.accessToken);
}

export function getIdToken(): string | null {
  return sessionStorage.getItem(STORAGE_KEYS.idToken);
}

export function getRefreshToken(): string | null {
  return sessionStorage.getItem(STORAGE_KEYS.refreshToken);
}

export function isTokenExpired(): boolean {
  const expiry = sessionStorage.getItem(STORAGE_KEYS.tokenExpiry);
  if (!expiry) return true;
  // Consider expired 60s before actual expiry to allow buffer for refresh
  return Date.now() > Number(expiry) - 60_000;
}

export function clearTokens(): void {
  sessionStorage.removeItem(STORAGE_KEYS.accessToken);
  sessionStorage.removeItem(STORAGE_KEYS.idToken);
  sessionStorage.removeItem(STORAGE_KEYS.refreshToken);
  sessionStorage.removeItem(STORAGE_KEYS.tokenExpiry);
}

export function storeCodeVerifier(verifier: string): void {
  sessionStorage.setItem(STORAGE_KEYS.codeVerifier, verifier);
}

export function getCodeVerifier(): string | null {
  return sessionStorage.getItem(STORAGE_KEYS.codeVerifier);
}

export function clearCodeVerifier(): void {
  sessionStorage.removeItem(STORAGE_KEYS.codeVerifier);
}

export function storeAuthState(state: string): void {
  sessionStorage.setItem(STORAGE_KEYS.authState, state);
}

export function getAuthState(): string | null {
  return sessionStorage.getItem(STORAGE_KEYS.authState);
}

export function clearAuthState(): void {
  sessionStorage.removeItem(STORAGE_KEYS.authState);
}

export function storeReturnUrl(url: string): void {
  sessionStorage.setItem(STORAGE_KEYS.returnUrl, url);
}

export function getReturnUrl(): string | null {
  return sessionStorage.getItem(STORAGE_KEYS.returnUrl);
}

export function clearReturnUrl(): void {
  sessionStorage.removeItem(STORAGE_KEYS.returnUrl);
}

export function getActiveTenantId(): string | null {
  return sessionStorage.getItem(STORAGE_KEYS.activeTenantId);
}

export function setActiveTenantId(tenantId: string): void {
  sessionStorage.setItem(STORAGE_KEYS.activeTenantId, tenantId);
}

export function clearActiveTenantId(): void {
  sessionStorage.removeItem(STORAGE_KEYS.activeTenantId);
}

// ─── Auth flow functions ─────────────────────────────────────────────────────

/**
 * Build the authorization URL for OIDC login with PKCE.
 * Stores the code verifier and state in sessionStorage for the callback.
 */
export async function buildAuthorizationUrl(config: AuthConfig): Promise<string> {
  const verifier = generateCodeVerifier();
  const challenge = await generateCodeChallenge(verifier);
  const state = generateState();

  storeCodeVerifier(verifier);
  storeAuthState(state);

  const endpoints = oidcEndpoints(config.issuer);
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    scope: config.scopes,
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });

  return `${endpoints.authorization}?${params.toString()}`;
}

/**
 * Exchange the authorization code for tokens.
 * Called from the /auth/callback page after the IdP redirects back.
 */
export async function exchangeCodeForTokens(
  config: AuthConfig,
  code: string,
): Promise<{
  access_token: string;
  id_token?: string;
  refresh_token?: string;
  expires_in?: number;
  token_type: string;
}> {
  const verifier = getCodeVerifier();
  if (!verifier) {
    throw new Error('Missing PKCE code verifier — login flow may have been interrupted.');
  }

  const endpoints = oidcEndpoints(config.issuer);
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: config.clientId,
    code,
    redirect_uri: config.redirectUri,
    code_verifier: verifier,
  });

  const res = await fetch(endpoints.token, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  if (!res.ok) {
    const errorBody = await res.text();
    throw new Error(`Token exchange failed: ${res.status} — ${errorBody}`);
  }

  const tokens = await res.json();
  clearCodeVerifier();
  clearAuthState();
  return tokens;
}

/**
 * Attempt to refresh the access token using the refresh token.
 * Returns null if no refresh token is available or refresh fails.
 */
export async function refreshAccessToken(
  config: AuthConfig,
): Promise<boolean> {
  const refreshToken = getRefreshToken();
  if (!refreshToken) return false;

  const endpoints = oidcEndpoints(config.issuer);
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    client_id: config.clientId,
    refresh_token: refreshToken,
  });

  try {
    const res = await fetch(endpoints.token, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    if (!res.ok) {
      clearTokens();
      return false;
    }

    const tokens = await res.json();
    storeTokens(tokens);
    return true;
  } catch {
    clearTokens();
    return false;
  }
}

/**
 * Build the logout URL for HCL IAM.
 */
export function buildLogoutUrl(config: AuthConfig): string {
  const idToken = getIdToken();
  const endpoints = oidcEndpoints(config.issuer);
  const params = new URLSearchParams({
    post_logout_redirect_uri: config.postLogoutRedirectUri,
  });
  if (idToken) {
    params.set('id_token_hint', idToken);
  }
  return `${endpoints.logout}?${params.toString()}`;
}

/**
 * Parse JWT claims without verification (for display purposes only).
 * The backend does the actual cryptographic verification.
 */
export function parseJwtClaims(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = parts[1];
    const decoded = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(decoded);
  } catch {
    return null;
  }
}
