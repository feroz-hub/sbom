import 'server-only';
import { readFileSync } from 'node:fs';
import { Agent, fetch as undiciFetch } from 'undici';
import { createRemoteJWKSet, customFetch, jwtVerify } from 'jose';
import type { ServerAuthConfig } from './server-config';
import type { TokenSession } from './session-store';

export interface Discovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  end_session_endpoint?: string;
  revocation_endpoint?: string;
}

let discoveryCache: { issuer: string; value: Discovery; expiresAt: number } | null = null;
const agents = new Map<string, Agent>();

function providerFetch(config: ServerAuthConfig): typeof globalThis.fetch {
  if (!config.caBundle) return globalThis.fetch;
  let dispatcher = agents.get(config.caBundle);
  if (!dispatcher) {
    dispatcher = new Agent({ connect: { ca: readFileSync(config.caBundle, 'utf8') } });
    agents.set(config.caBundle, dispatcher);
  }
  return ((input: Parameters<typeof globalThis.fetch>[0], init?: Parameters<typeof globalThis.fetch>[1]) =>
    undiciFetch(input as string | URL, { ...(init || {}), dispatcher } as Parameters<typeof undiciFetch>[1])
  ) as unknown as typeof globalThis.fetch;
}

function trustedEndpoint(value: string, issuer: string): string {
  const endpoint = new URL(value);
  const authority = new URL(issuer);
  if (endpoint.protocol !== 'https:' || endpoint.origin !== authority.origin) {
    throw new Error('OIDC metadata contains an untrusted endpoint');
  }
  return endpoint.toString();
}

export async function getDiscovery(config: ServerAuthConfig): Promise<Discovery> {
  if (discoveryCache?.issuer === config.issuer && discoveryCache.expiresAt > Date.now()) return discoveryCache.value;
  const response = await providerFetch(config)(`${config.issuer}/.well-known/openid-configuration`, {
    signal: AbortSignal.timeout(5_000),
    cache: 'no-store',
  });
  if (!response.ok) throw new Error('OIDC discovery is unavailable');
  const raw = (await response.json()) as Discovery;
  if (raw.issuer !== config.issuer) throw new Error('OIDC discovery issuer mismatch');
  const value: Discovery = {
    ...raw,
    authorization_endpoint: trustedEndpoint(raw.authorization_endpoint, config.issuer),
    token_endpoint: trustedEndpoint(raw.token_endpoint, config.issuer),
    jwks_uri: trustedEndpoint(raw.jwks_uri, config.issuer),
    end_session_endpoint: raw.end_session_endpoint
      ? trustedEndpoint(raw.end_session_endpoint, config.issuer)
      : undefined,
    revocation_endpoint: raw.revocation_endpoint
      ? trustedEndpoint(raw.revocation_endpoint, config.issuer)
      : undefined,
  };
  discoveryCache = { issuer: config.issuer, value, expiresAt: Date.now() + 5 * 60_000 };
  return value;
}

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

export async function validateIdToken(
  token: string,
  nonce: string,
  config: ServerAuthConfig,
  discovery: Discovery,
): Promise<void> {
  let jwks = jwksCache.get(discovery.jwks_uri);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(discovery.jwks_uri), {
      timeoutDuration: 5_000,
      cooldownDuration: 10_000,
      cacheMaxAge: 5 * 60_000,
      [customFetch]: providerFetch(config),
    });
    jwksCache.set(discovery.jwks_uri, jwks);
  }
  await jwtVerify(token, jwks, {
    issuer: config.issuer,
    audience: config.clientId,
    algorithms: ['RS256'],
    requiredClaims: ['sub', 'exp', 'iat', 'nonce'],
  }).then(({ payload }) => {
    if (payload.nonce !== nonce) throw new Error('OIDC nonce validation failed');
  });
}

async function tokenRequest(
  endpoint: string,
  body: URLSearchParams,
  config: ServerAuthConfig,
): Promise<Record<string, unknown>> {
  const response = await providerFetch(config)(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
    signal: AbortSignal.timeout(10_000),
    cache: 'no-store',
  });
  if (!response.ok) throw new Error('OIDC token request failed');
  return (await response.json()) as Record<string, unknown>;
}

function toSession(tokens: Record<string, unknown>, previous?: TokenSession): TokenSession {
  if (typeof tokens.access_token !== 'string' || !tokens.access_token) throw new Error('OIDC access token missing');
  const expiresIn = typeof tokens.expires_in === 'number' ? tokens.expires_in : 300;
  return {
    accessToken: tokens.access_token,
    refreshToken: typeof tokens.refresh_token === 'string' ? tokens.refresh_token : previous?.refreshToken,
    idToken: typeof tokens.id_token === 'string' ? tokens.id_token : previous?.idToken,
    expiresAt: Date.now() + expiresIn * 1000,
    createdAt: previous?.createdAt ?? Date.now(),
  };
}

export async function exchangeCode(
  code: string,
  verifier: string,
  nonce: string,
  config: ServerAuthConfig,
  discovery: Discovery,
): Promise<TokenSession> {
  let tokens: Record<string, unknown>;
  try {
    tokens = await tokenRequest(discovery.token_endpoint, new URLSearchParams({
      grant_type: 'authorization_code', client_id: config.clientId, code,
      redirect_uri: config.redirectUri, code_verifier: verifier,
    }), config);
  } catch (error) {
    throw new Error('OIDC authorization-code exchange failed', { cause: error });
  }
  if (typeof tokens.id_token !== 'string') throw new Error('OIDC ID token missing');
  try {
    await validateIdToken(tokens.id_token, nonce, config, discovery);
  } catch (error) {
    throw new Error('OIDC ID token validation failed', { cause: error });
  }
  return toSession(tokens);
}

export async function refreshTokens(
  previous: TokenSession,
  config: ServerAuthConfig,
  discovery: Discovery,
): Promise<TokenSession | null> {
  if (!previous.refreshToken) return null;
  try {
    const tokens = await tokenRequest(discovery.token_endpoint, new URLSearchParams({
      grant_type: 'refresh_token', client_id: config.clientId, refresh_token: previous.refreshToken,
    }), config);
    return toSession(tokens, previous);
  } catch {
    return null;
  }
}

export async function revokeToken(
  token: string,
  config: ServerAuthConfig,
  discovery: Discovery,
): Promise<void> {
  if (!discovery.revocation_endpoint) return;
  await providerFetch(config)(discovery.revocation_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ token, client_id: config.clientId }),
    signal: AbortSignal.timeout(5_000),
    cache: 'no-store',
  });
}
