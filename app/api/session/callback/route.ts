import { NextRequest, NextResponse } from 'next/server';
import { serverSessionConfig } from '@/lib/server-session/config';
import { takePendingSignIn } from '@/lib/server-session/flow';
import { discover, exchangeCode, OidcRefusedError, OidcUnavailableError, verifyIdToken } from '@/lib/server-session/oidc';
import { createSession, endSession, loadSession, readSessionId, setSessionCookie } from '@/lib/server-session/session';
import { logger } from '@/lib/logger';

/**
 * GET /api/session/callback: the provider's answer to a sign-in.
 *
 * Checks, in order: the flow cookie for this state exists and is fresh (CSRF
 * and replay), the issuer parameter names our provider (RFC 9207, mix-up),
 * the code redeems with our verifier (PKCE), and the ID token is ours, signed,
 * current and carries our nonce. Only then is there a session.
 */
export const dynamic = 'force-dynamic';

export async function GET(request: NextRequest) {
  const config = serverSessionConfig();
  if (!config) return NextResponse.json({ error: 'not_configured' }, { status: 404 });

  const params = request.nextUrl.searchParams;
  const base = `${config.publicOrigin}${request.nextUrl.basePath}`;
  const fail = (reason: string, response?: NextResponse) => {
    const target = NextResponse.redirect(`${base}/login?signin_error=${encodeURIComponent(reason)}`, 303);
    // Carry the spent flow cookie's deletion over to the redirect we actually send.
    response?.cookies.getAll().forEach((cookie) => target.cookies.set(cookie));
    target.headers.set('Cache-Control', 'no-store');
    return target;
  };

  const state = params.get('state') ?? '';
  const scratch = NextResponse.next();
  const pending = takePendingSignIn(request, scratch, config, state);
  if (!pending) return fail('expired', scratch);

  const providerError = params.get('error');
  if (providerError) {
    // access_denied is the user choosing not to sign in; the rest are worth a log line.
    if (providerError !== 'access_denied') logger.warn('Sign-in: provider returned an error', { error: providerError });
    return fail(providerError === 'access_denied' ? 'cancelled' : 'failed', scratch);
  }

  try {
    const discovery = await discover(config);
    const iss = params.get('iss');
    if (iss !== null ? iss !== config.issuer : discovery.authorization_response_iss_parameter_supported === true) {
      logger.warn('Sign-in: issuer parameter missing or wrong', { iss });
      return fail('failed', scratch);
    }

    const code = params.get('code');
    if (!code) return fail('failed', scratch);
    const tokens = await exchangeCode(config, code, pending.verifier);
    if (!tokens.idToken) {
      logger.error('Sign-in: token response carried no ID token; is "openid" in the client scopes?');
      return fail('failed', scratch);
    }
    const claims = await verifyIdToken(config, tokens.idToken, { nonce: pending.nonce });

    // Signing in again in a browser that already had a session replaces it.
    const previous = readSessionId(request, config);
    if (previous) {
      const old = await loadSession(config, previous);
      await endSession(config, previous, old);
    }

    const { sid, record } = await createSession(config, tokens, claims, pending.persistent);
    const response = NextResponse.redirect(`${base}${pending.returnTo}`, 303);
    scratch.cookies.getAll().forEach((cookie) => response.cookies.set(cookie));
    setSessionCookie(response, config, sid, record);
    response.headers.set('Cache-Control', 'no-store');
    response.headers.set('Referrer-Policy', 'no-referrer');
    logger.info('Sign-in completed', { amr: claims.amr?.join(',') ?? '' });
    return response;
  } catch (error) {
    if (error instanceof OidcRefusedError) {
      logger.warn('Sign-in refused', { code: error.code, status: error.status });
      return fail('failed', scratch);
    }
    if (error instanceof OidcUnavailableError) {
      logger.warn('Sign-in: provider unavailable', { error: error.message });
      return fail('unavailable', scratch);
    }
    logger.error('Sign-in: unexpected error', { error: error instanceof Error ? error.message : String(error) });
    return fail('failed', scratch);
  }
}
