import type { NextRequest } from 'next/server';
import { serverSessionConfig } from './config';
import { accessToken, loadSession, readSessionId } from './session';
import type { StalwartCredentials } from '@/lib/stalwart/credentials';

/**
 * Mail server credentials for this request's server-held session.
 *
 * undefined: server-held sign-in is not configured (callers fall back to the
 * page-synced context). null: it is, and this request has no live session.
 * A provider outage while renewing reads as null too: these routes are
 * auxiliary, and the page learns about outages from /api/mail.
 */
export async function serverSessionCredentials(request: NextRequest): Promise<StalwartCredentials | null | undefined> {
  const config = serverSessionConfig();
  if (!config) return undefined;
  const sid = readSessionId(request, config);
  const record = sid ? await loadSession(config, sid) : null;
  if (!sid || !record) return null;
  let access;
  try {
    access = await accessToken(config, sid, record);
  } catch {
    return null;
  }
  if (access.kind === 'ended') return null;
  return {
    serverUrl: process.env.JMAP_UPSTREAM_ORIGIN || config.issuer,
    authHeader: `Bearer ${access.accessToken}`,
    username: access.record.username,
    accountName: access.record.username,
    hasSessionCookie: true,
    slot: 0,
    trusted: true,
  };
}
