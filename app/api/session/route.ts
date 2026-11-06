import { NextRequest, NextResponse } from 'next/server';
import { serverSessionConfig } from '@/lib/server-session/config';
import { endSessionUrl } from '@/lib/server-session/oidc';
import { clearSessionCookie, endSession, loadSession, readSessionId } from '@/lib/server-session/session';
import { rejectCrossOriginRequest } from '@/lib/security/same-origin';

/**
 * GET    /api/session  who is signed in in this browser, or 401
 * DELETE /api/session  sign out: the session here, its grant at the
 *                      provider, and the URL that ends the provider's own
 *                      session, for the page to go to next
 */
export const dynamic = 'force-dynamic';

const NO_STORE = { 'Cache-Control': 'no-store' };

export async function GET(request: NextRequest) {
  const config = serverSessionConfig();
  if (!config) return NextResponse.json({ error: 'not_configured' }, { status: 404, headers: NO_STORE });
  const sid = readSessionId(request, config);
  const record = sid ? await loadSession(config, sid) : null;
  if (!record) {
    const response = NextResponse.json({ authenticated: false }, { status: 401, headers: NO_STORE });
    if (sid) clearSessionCookie(response, config);
    return response;
  }
  return NextResponse.json(
    {
      authenticated: true,
      user: { username: record.username, name: record.name },
      persistent: record.persistent,
      signedInAt: record.createdAt,
      authTime: record.authTime,
      amr: record.amr,
    },
    { headers: NO_STORE },
  );
}

export async function DELETE(request: NextRequest) {
  const crossOrigin = rejectCrossOriginRequest(request);
  if (crossOrigin) return crossOrigin;
  const config = serverSessionConfig();
  if (!config) return NextResponse.json({ error: 'not_configured' }, { status: 404, headers: NO_STORE });
  const sid = readSessionId(request, config);
  const record = sid ? await loadSession(config, sid) : null;
  const next = await endSessionUrl(config, record?.idToken ?? null);
  if (sid) await endSession(config, sid, record);
  const response = NextResponse.json({ endSessionUrl: next }, { headers: NO_STORE });
  clearSessionCookie(response, config);
  return response;
}
