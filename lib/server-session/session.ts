import type { NextRequest, NextResponse } from 'next/server';
import { isSecureOrigin, type ServerSessionConfig } from './config';
import { OidcRefusedError, randomToken, refreshTokens, revokeToken, verifyIdToken, type IdTokenClaims, type TokenSet } from './oidc';
import { deleteSession, isExpired, readSession, sessionKey, sweepSessions, writeSession, type SessionRecord } from './store';

/**
 * The browser's half of a server-held sign-in: one opaque, httpOnly cookie.
 *
 * Reloads, new tabs and restarts of this server all find the same record, and
 * only this server ever spends the refresh token, one refresh at a time per
 * session. That is what makes a reload unable to sign anyone out: there is no
 * token in the page to lose, and no refresh the page can abandon halfway.
 */

/** Renew this long before the access token runs out. */
const REFRESH_MARGIN_SECONDS = 60;
/** lastSeenAt is written at most this often; idle limits are days, not minutes. */
const TOUCH_INTERVAL_SECONDS = 300;
const SWEEP_INTERVAL_MS = 60 * 60 * 1000;

export function sessionCookieName(config: ServerSessionConfig): string {
  return isSecureOrigin(config) ? '__Host-bmail_session' : 'bmail_session';
}

export function readSessionId(request: NextRequest, config: ServerSessionConfig): string | null {
  const value = request.cookies.get(sessionCookieName(config))?.value;
  // 32 random bytes, base64url: anything else was not minted here.
  return value && /^[A-Za-z0-9_-]{43}$/.test(value) ? value : null;
}

export function setSessionCookie(response: NextResponse, config: ServerSessionConfig, sid: string, record: SessionRecord): void {
  const now = Math.floor(Date.now() / 1000);
  response.cookies.set(sessionCookieName(config), sid, {
    httpOnly: true,
    secure: isSecureOrigin(config),
    // Lax, not Strict: a link to a message from another site should open signed in.
    sameSite: 'lax',
    path: '/',
    ...(record.persistent ? { maxAge: Math.max(0, record.expiresAt - now) } : {}),
  });
}

export function clearSessionCookie(response: NextResponse, config: ServerSessionConfig): void {
  response.cookies.set(sessionCookieName(config), '', {
    httpOnly: true,
    secure: isSecureOrigin(config),
    sameSite: 'lax',
    path: '/',
    maxAge: 0,
  });
}

function idleLimits(config: ServerSessionConfig) {
  return { persistent: config.persistentIdleSeconds, transient: config.transientIdleSeconds };
}

let sweeper: ReturnType<typeof setInterval> | null = null;
function startSweeper(config: ServerSessionConfig): void {
  if (sweeper) return;
  const run = () => void sweepSessions(idleLimits(config)).catch(() => {});
  sweeper = setInterval(run, SWEEP_INTERVAL_MS);
  sweeper.unref?.();
  run();
}

export function usernameFromClaims(claims: IdTokenClaims): string {
  return claims.email || claims.preferred_username || claims.sub;
}

/** A new session from a completed sign-in. Returns the cookie value to set. */
export async function createSession(
  config: ServerSessionConfig,
  tokens: TokenSet,
  claims: IdTokenClaims,
  persistent: boolean,
): Promise<{ sid: string; record: SessionRecord }> {
  startSweeper(config);
  const now = Math.floor(Date.now() / 1000);
  const sid = randomToken(32);
  const record: SessionRecord = {
    v: 1,
    sub: claims.sub,
    username: usernameFromClaims(claims),
    name: claims.name || '',
    createdAt: now,
    lastSeenAt: now,
    expiresAt: now + config.absoluteSeconds,
    persistent,
    accessToken: tokens.accessToken,
    accessExpiresAt: tokens.accessExpiresAt,
    refreshToken: tokens.refreshToken,
    idToken: tokens.idToken,
    authTime: claims.auth_time ?? now,
    amr: claims.amr ?? [],
  };
  await writeSession(sid, record);
  return { sid, record };
}

/** The live session for this cookie, or null. Expired records are removed on sight. */
export async function loadSession(config: ServerSessionConfig, sid: string): Promise<SessionRecord | null> {
  startSweeper(config);
  const record = await readSession(sid);
  if (!record) return null;
  if (isExpired(record, idleLimits(config))) {
    await endSession(config, sid, record);
    return null;
  }
  const now = Math.floor(Date.now() / 1000);
  if (now - record.lastSeenAt >= TOUCH_INTERVAL_SECONDS) {
    const touched = { ...record, lastSeenAt: now };
    await writeSession(sid, touched).catch(() => {});
    return touched;
  }
  return record;
}

/** The outcome of asking for a usable access token. */
export type AccessResult =
  | { kind: 'ok'; accessToken: string; record: SessionRecord }
  /** The provider refused the grant: the session is over and has been removed. */
  | { kind: 'ended' };

const inFlight = new Map<string, Promise<AccessResult>>();

/**
 * An access token with at least a minute left, renewing it first if needed.
 * `force` renews even a token that looks valid (the resource server just
 * refused it). Concurrent callers for one session share one refresh.
 *
 * Throws OidcUnavailableError when the provider can't be reached: the session
 * stays, and the caller reports an outage rather than a sign-out.
 */
export async function accessToken(
  config: ServerSessionConfig,
  sid: string,
  record: SessionRecord,
  force = false,
): Promise<AccessResult> {
  const now = Math.floor(Date.now() / 1000);
  if (!force && record.accessExpiresAt - REFRESH_MARGIN_SECONDS > now) {
    return { kind: 'ok', accessToken: record.accessToken, record };
  }
  const key = sessionKey(sid);
  const running = inFlight.get(key);
  if (running) return running;

  const refresh = (async (): Promise<AccessResult> => {
    // Another request may have renewed it between our read and now.
    const latest = (await readSession(sid)) ?? record;
    if (!force && latest.accessExpiresAt - REFRESH_MARGIN_SECONDS > Math.floor(Date.now() / 1000)) {
      return { kind: 'ok', accessToken: latest.accessToken, record: latest };
    }
    if (force && latest.accessToken !== record.accessToken) {
      // Someone renewed it already; the refused token was the old one.
      return { kind: 'ok', accessToken: latest.accessToken, record: latest };
    }
    if (!latest.refreshToken) {
      await endSession(config, sid, latest);
      return { kind: 'ended' };
    }
    let tokens: TokenSet;
    try {
      tokens = await refreshTokens(config, latest.refreshToken);
    } catch (error) {
      // Only invalid_grant says the sign-in itself is over (RFC 6749 §5.2).
      if (error instanceof OidcRefusedError && error.code === 'invalid_grant') {
        await endSession(config, sid, latest, false);
        return { kind: 'ended' };
      }
      // invalid_client and the rest are this server's misconfiguration, not the
      // user's session ending: keep the session while the operator fixes it.
      throw error;
    }
    let claims: IdTokenClaims | null = null;
    if (tokens.idToken) {
      claims = await verifyIdToken(config, tokens.idToken, { sub: latest.sub });
    }
    const renewed: SessionRecord = {
      ...latest,
      accessToken: tokens.accessToken,
      accessExpiresAt: tokens.accessExpiresAt,
      // Rotation: a provider that rotates returns a new one; one that doesn't, doesn't.
      refreshToken: tokens.refreshToken ?? latest.refreshToken,
      idToken: tokens.idToken ?? latest.idToken,
      name: claims?.name || latest.name,
    };
    await writeSession(sid, renewed);
    return { kind: 'ok', accessToken: renewed.accessToken, record: renewed };
  })();

  inFlight.set(key, refresh);
  try {
    return await refresh;
  } finally {
    inFlight.delete(key);
  }
}

/** Remove the session here and, best effort, its grant at the provider. */
export async function endSession(
  config: ServerSessionConfig,
  sid: string,
  record: SessionRecord | null,
  revoke = true,
): Promise<void> {
  await deleteSession(sid);
  if (revoke && record?.refreshToken) await revokeToken(config, record.refreshToken);
}
