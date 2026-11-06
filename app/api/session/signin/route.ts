import { NextRequest, NextResponse } from 'next/server';
import { serverSessionConfig } from '@/lib/server-session/config';
import { safeReturnTo, setPendingSignIn } from '@/lib/server-session/flow';
import { authorizationUrl, OidcUnavailableError, randomToken } from '@/lib/server-session/oidc';
import { loadSession, readSessionId } from '@/lib/server-session/session';
import { logger } from '@/lib/logger';

/**
 * GET /api/session/signin: leave for the provider's sign-in page.
 *
 *   returnTo   same-origin path to land on afterwards (default "/")
 *   persistent "0" for a session that ends with the browser (default: stay signed in)
 *   prompt     "login" to make the provider ask again even when it knows the user
 *   login_hint the address to prefill there
 *
 * A browser that is already signed in, and didn't ask to be asked again, goes
 * straight to returnTo.
 */
export const dynamic = 'force-dynamic';

export async function GET(request: NextRequest) {
  const config = serverSessionConfig();
  if (!config) return NextResponse.json({ error: 'not_configured' }, { status: 404 });

  const params = request.nextUrl.searchParams;
  const returnTo = safeReturnTo(params.get('returnTo'));
  const prompt = params.get('prompt') === 'login' ? 'login' : undefined;
  const base = `${config.publicOrigin}${request.nextUrl.basePath}`;

  if (!prompt) {
    const sid = readSessionId(request, config);
    if (sid && (await loadSession(config, sid))) {
      return NextResponse.redirect(`${base}${returnTo}`, 303);
    }
  }

  const loginHint = params.get('login_hint')?.slice(0, 320) || undefined;
  const pending = {
    state: randomToken(32),
    nonce: randomToken(32),
    verifier: randomToken(48),
    returnTo,
    persistent: params.get('persistent') !== '0',
    startedAt: Math.floor(Date.now() / 1000),
  };

  let target: string;
  try {
    target = await authorizationUrl(config, { ...pending, loginHint, prompt });
  } catch (error) {
    logger.error('Sign-in: provider discovery failed', { error: error instanceof Error ? error.message : String(error) });
    const reason = error instanceof OidcUnavailableError ? 'unavailable' : 'failed';
    return NextResponse.redirect(`${base}/login?signin_error=${reason}`, 303);
  }

  const response = NextResponse.redirect(target, 303);
  setPendingSignIn(response, config, pending);
  response.headers.set('Cache-Control', 'no-store');
  response.headers.set('Referrer-Policy', 'no-referrer');
  return response;
}
