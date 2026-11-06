import { createHash, randomBytes, webcrypto } from 'node:crypto';
import type { ServerSessionConfig } from './config';

/**
 * The OpenID Connect relying party, confidential client, authorization code
 * flow with PKCE (S256), state, nonce and RFC 9207 issuer identification.
 *
 * Deliberately narrow: one issuer, fixed at deploy time, whose discovery
 * document must name itself exactly; ID tokens signed ES256 by a key in its
 * JWKS. Anything outside that is refused rather than negotiated.
 */

const HTTP_TIMEOUT_MS = 10_000;
const DISCOVERY_TTL_MS = 60 * 60 * 1000;
const JWKS_MIN_REFETCH_MS = 60 * 1000;
const CLOCK_SKEW_SECONDS = 60;

export interface Discovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  revocation_endpoint?: string;
  end_session_endpoint?: string;
  userinfo_endpoint?: string;
  authorization_response_iss_parameter_supported?: boolean;
}

export interface TokenSet {
  accessToken: string;
  /** Unix seconds. */
  accessExpiresAt: number;
  refreshToken: string | null;
  idToken: string | null;
}

export interface IdTokenClaims {
  sub: string;
  email?: string;
  name?: string;
  preferred_username?: string;
  auth_time?: number;
  amr?: string[];
  acr?: string;
  sid?: string;
}

/** The provider said no: the grant, code or client is not accepted. */
export class OidcRefusedError extends Error {
  constructor(readonly code: string, readonly status: number) {
    super(`OIDC request refused: ${code} (${status})`);
  }
}

/** The provider could not be reached or answered with a server error. */
export class OidcUnavailableError extends Error {}

let discoveryCache: { value: Discovery; at: number; issuer: string } | null = null;
let jwksCache: { keys: Map<string, webcrypto.CryptoKey>; at: number; uri: string } | null = null;

async function fetchJson(url: string, init?: RequestInit): Promise<{ status: number; body: Record<string, unknown> }> {
  let response: Response;
  try {
    response = await fetch(url, {
      ...init,
      redirect: 'error',
      cache: 'no-store',
      signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
      headers: { accept: 'application/json', ...(init?.headers ?? {}) },
    });
  } catch (error) {
    throw new OidcUnavailableError(error instanceof Error ? error.message : 'network error');
  }
  if (response.status >= 500 || response.status === 429) {
    throw new OidcUnavailableError(`HTTP ${response.status} from ${new URL(url).pathname}`);
  }
  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    if (response.ok) throw new OidcUnavailableError(`Malformed JSON from ${new URL(url).pathname}`);
    body = {};
  }
  return { status: response.status, body: body as Record<string, unknown> };
}

function sameOrigin(url: string, issuer: string): boolean {
  try {
    return new URL(url).origin === new URL(issuer).origin && new URL(url).protocol === new URL(issuer).protocol;
  } catch {
    return false;
  }
}

export async function discover(config: ServerSessionConfig): Promise<Discovery> {
  if (discoveryCache && discoveryCache.issuer === config.issuer && Date.now() - discoveryCache.at < DISCOVERY_TTL_MS) {
    return discoveryCache.value;
  }
  const { status, body } = await fetchJson(`${config.issuer}/.well-known/openid-configuration`);
  if (status !== 200) throw new OidcUnavailableError(`Discovery answered ${status}`);
  const value = body as unknown as Discovery;
  // OpenID Connect Discovery 1.0 §4.3: the document must name the issuer it was fetched for.
  if (value.issuer !== config.issuer) throw new OidcUnavailableError('Discovery issuer mismatch');
  for (const key of ['authorization_endpoint', 'token_endpoint', 'jwks_uri'] as const) {
    if (typeof value[key] !== 'string' || !sameOrigin(value[key], config.issuer)) {
      throw new OidcUnavailableError(`Discovery ${key} missing or off-origin`);
    }
  }
  for (const key of ['revocation_endpoint', 'end_session_endpoint', 'userinfo_endpoint'] as const) {
    if (value[key] !== undefined && (typeof value[key] !== 'string' || !sameOrigin(value[key]!, config.issuer))) {
      delete value[key];
    }
  }
  discoveryCache = { value, at: Date.now(), issuer: config.issuer };
  return value;
}

async function signingKey(discovery: Discovery, kid: string | undefined): Promise<webcrypto.CryptoKey | null> {
  const lookup = () => {
    if (!jwksCache || jwksCache.uri !== discovery.jwks_uri) return null;
    if (kid) return jwksCache.keys.get(kid) ?? null;
    return jwksCache.keys.size === 1 ? [...jwksCache.keys.values()][0] : null;
  };
  const hit = lookup();
  if (hit) return hit;
  // An unknown kid is how a key rotation looks from here: refetch, but not on every token.
  if (jwksCache && jwksCache.uri === discovery.jwks_uri && Date.now() - jwksCache.at < JWKS_MIN_REFETCH_MS) return null;

  const { status, body } = await fetchJson(discovery.jwks_uri);
  if (status !== 200 || !Array.isArray(body.keys)) throw new OidcUnavailableError('JWKS unavailable');
  const keys = new Map<string, webcrypto.CryptoKey>();
  for (const jwk of body.keys as Array<Record<string, unknown>>) {
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || (jwk.use !== undefined && jwk.use !== 'sig')) continue;
    if (jwk.alg !== undefined && jwk.alg !== 'ES256') continue;
    try {
      const key = await webcrypto.subtle.importKey(
        'jwk',
        { kty: 'EC', crv: 'P-256', x: jwk.x as string, y: jwk.y as string },
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify'],
      );
      keys.set(typeof jwk.kid === 'string' ? jwk.kid : '', key);
    } catch {
      // A malformed key is skipped, not fatal: the others may still verify.
    }
  }
  jwksCache = { keys, at: Date.now(), uri: discovery.jwks_uri };
  return lookup();
}

function decodeSegment(segment: string): Record<string, unknown> {
  const parsed: unknown = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not an object');
  return parsed as Record<string, unknown>;
}

/**
 * Verify an ID token per OpenID Connect Core §3.1.3.7. `nonce` is required on
 * the sign-in response and absent on refresh (§12.2: a refreshed ID token
 * carries no new nonce, and its sub must match the original).
 */
export async function verifyIdToken(
  config: ServerSessionConfig,
  token: string,
  expect: { nonce?: string; sub?: string },
): Promise<IdTokenClaims> {
  const parts = token.split('.');
  if (parts.length !== 3) throw new OidcRefusedError('invalid_id_token', 0);
  let header: Record<string, unknown>;
  let claims: Record<string, unknown>;
  try {
    header = decodeSegment(parts[0]);
    claims = decodeSegment(parts[1]);
  } catch {
    throw new OidcRefusedError('invalid_id_token', 0);
  }
  if (header.alg !== 'ES256') throw new OidcRefusedError('invalid_id_token_alg', 0);

  const discovery = await discover(config);
  const key = await signingKey(discovery, typeof header.kid === 'string' ? header.kid : undefined);
  if (!key) throw new OidcRefusedError('unknown_signing_key', 0);
  const valid = await webcrypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    Buffer.from(parts[2], 'base64url'),
    Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii'),
  );
  if (!valid) throw new OidcRefusedError('invalid_id_token_signature', 0);

  const now = Math.floor(Date.now() / 1000);
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  const fail = (what: string) => {
    throw new OidcRefusedError(`invalid_id_token_${what}`, 0);
  };
  if (claims.iss !== config.issuer) fail('iss');
  if (!aud.includes(config.clientId)) fail('aud');
  if (aud.length > 1 && claims.azp !== config.clientId) fail('azp');
  if (typeof claims.exp !== 'number' || claims.exp + CLOCK_SKEW_SECONDS < now) fail('exp');
  if (typeof claims.iat !== 'number' || claims.iat - CLOCK_SKEW_SECONDS > now) fail('iat');
  if (typeof claims.sub !== 'string' || !claims.sub) fail('sub');
  if (expect.nonce !== undefined && claims.nonce !== expect.nonce) fail('nonce');
  if (expect.sub !== undefined && claims.sub !== expect.sub) fail('sub');

  return {
    sub: claims.sub as string,
    email: typeof claims.email === 'string' ? claims.email : undefined,
    name: typeof claims.name === 'string' ? claims.name : undefined,
    preferred_username: typeof claims.preferred_username === 'string' ? claims.preferred_username : undefined,
    auth_time: typeof claims.auth_time === 'number' ? claims.auth_time : undefined,
    amr: Array.isArray(claims.amr) ? claims.amr.filter((v): v is string => typeof v === 'string') : undefined,
    acr: typeof claims.acr === 'string' ? claims.acr : undefined,
    sid: typeof claims.sid === 'string' ? claims.sid : undefined,
  };
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

export function pkceChallenge(verifier: string): string {
  return createHash('sha256').update(verifier, 'ascii').digest('base64url');
}

export function redirectUri(config: ServerSessionConfig): string {
  return `${config.publicOrigin}/api/session/callback`;
}

export async function authorizationUrl(
  config: ServerSessionConfig,
  request: { state: string; nonce: string; verifier: string; loginHint?: string; prompt?: 'login' | 'select_account' | 'none' },
): Promise<string> {
  const discovery = await discover(config);
  const url = new URL(discovery.authorization_endpoint);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', config.clientId);
  url.searchParams.set('redirect_uri', redirectUri(config));
  url.searchParams.set('scope', config.scopes);
  url.searchParams.set('state', request.state);
  url.searchParams.set('nonce', request.nonce);
  url.searchParams.set('code_challenge', pkceChallenge(request.verifier));
  url.searchParams.set('code_challenge_method', 'S256');
  if (request.loginHint) url.searchParams.set('login_hint', request.loginHint);
  if (request.prompt) url.searchParams.set('prompt', request.prompt);
  return url.toString();
}

async function tokenRequest(config: ServerSessionConfig, params: Record<string, string>): Promise<TokenSet> {
  const discovery = await discover(config);
  // client_secret_basic, RFC 6749 §2.3.1: both halves form-encoded before base64.
  const basic = Buffer.from(
    `${encodeURIComponent(config.clientId)}:${encodeURIComponent(config.clientSecret)}`,
  ).toString('base64');
  const { status, body } = await fetchJson(discovery.token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${basic}` },
    body: new URLSearchParams(params).toString(),
  });
  if (status !== 200) {
    throw new OidcRefusedError(typeof body.error === 'string' ? body.error : 'invalid_request', status);
  }
  if (typeof body.access_token !== 'string' || !body.access_token) {
    throw new OidcUnavailableError('Token response without access_token');
  }
  if (typeof body.token_type !== 'string' || body.token_type.toLowerCase() !== 'bearer') {
    throw new OidcUnavailableError('Token response is not a bearer token');
  }
  const expiresIn = typeof body.expires_in === 'number' && body.expires_in > 0 ? body.expires_in : 300;
  return {
    accessToken: body.access_token,
    accessExpiresAt: Math.floor(Date.now() / 1000) + expiresIn,
    refreshToken: typeof body.refresh_token === 'string' && body.refresh_token ? body.refresh_token : null,
    idToken: typeof body.id_token === 'string' && body.id_token ? body.id_token : null,
  };
}

export function exchangeCode(config: ServerSessionConfig, code: string, verifier: string): Promise<TokenSet> {
  return tokenRequest(config, {
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri(config),
    code_verifier: verifier,
  });
}

export function refreshTokens(config: ServerSessionConfig, refreshToken: string): Promise<TokenSet> {
  return tokenRequest(config, { grant_type: 'refresh_token', refresh_token: refreshToken });
}

/** RFC 7009. Best effort: a sign-out never waits on, or fails because of, the provider. */
export async function revokeToken(config: ServerSessionConfig, token: string): Promise<void> {
  try {
    const discovery = await discover(config);
    if (!discovery.revocation_endpoint) return;
    const basic = Buffer.from(
      `${encodeURIComponent(config.clientId)}:${encodeURIComponent(config.clientSecret)}`,
    ).toString('base64');
    await fetch(discovery.revocation_endpoint, {
      method: 'POST',
      redirect: 'error',
      signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${basic}` },
      body: new URLSearchParams({ token, token_type_hint: 'refresh_token' }).toString(),
    });
  } catch {
    // Nothing to do: the local session is gone either way.
  }
}

/** RP-initiated logout 1.0, or null when the provider has no end-session endpoint. */
export async function endSessionUrl(config: ServerSessionConfig, idToken: string | null): Promise<string | null> {
  let discovery: Discovery;
  try {
    discovery = await discover(config);
  } catch {
    return null;
  }
  if (!discovery.end_session_endpoint) return null;
  const url = new URL(discovery.end_session_endpoint);
  url.searchParams.set('client_id', config.clientId);
  url.searchParams.set('post_logout_redirect_uri', `${config.publicOrigin}/`);
  if (idToken) url.searchParams.set('id_token_hint', idToken);
  return url.toString();
}

/** For tests. */
export function resetOidcCaches(): void {
  discoveryCache = null;
  jwksCache = null;
}
