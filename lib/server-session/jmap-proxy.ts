import { NextRequest, NextResponse } from 'next/server';
import { serverSessionConfig, type ServerSessionConfig } from './config';
import { OidcRefusedError, OidcUnavailableError } from './oidc';
import { accessToken, clearSessionCookie, endSession, loadSession, readSessionId } from './session';
import { isSameOriginRequest } from '@/lib/security/same-origin';
import { logger } from '@/lib/logger';

/**
 * The browser's only way to the mail server: same origin, no token in the page.
 *
 * /api/mail/.well-known/jmap and /api/mail/jmap/** are forwarded to the mail
 * server with the session's bearer token added here. The session resource is
 * rewritten so every URL in it points back under /api/mail, which keeps the
 * JMAP client unaware that a proxy exists.
 *
 * Status contract with the page: 401 means the sign-in is over (go sign in),
 * 503 means the provider or mail server is unreachable (keep the session,
 * retry). Everything else is the mail server's own answer.
 */

export const MAIL_PREFIX = '/api/mail';

const FORWARD_REQUEST_HEADERS = [
  'accept',
  'accept-language',
  'content-type',
  'if-modified-since',
  'if-none-match',
  'last-event-id',
  'range',
];

const FORWARD_RESPONSE_HEADERS = [
  'accept-ranges',
  'cache-control',
  'content-disposition',
  'content-range',
  'content-type',
  'etag',
  'last-modified',
  'retry-after',
];

/** Requests above this are refused rather than buffered for a retry. Uploads stream. */
const MAX_BUFFERED_BODY = 64 * 1024 * 1024;
const API_TIMEOUT_MS = 120_000;

type Route =
  | { kind: 'session'; upstreamPath: string }
  | { kind: 'api' | 'download' | 'upload' | 'eventsource' | 'other'; upstreamPath: string };

function route(segments: string[]): Route | null {
  if (segments.some((s) => s === '' || s === '.' || s === '..' || s.includes('/') || s.includes('\\'))) return null;
  const joined = segments.join('/');
  // The discovery URL is a redirect to the session resource; answer it directly.
  if (joined === '.well-known/jmap' || joined === 'jmap/session') return { kind: 'session', upstreamPath: '/jmap/session' };
  if (segments[0] !== 'jmap') return null;
  const encoded = '/' + segments.map(encodeURIComponent).join('/');
  if (segments.length === 1) return { kind: 'api', upstreamPath: '/jmap/' };
  switch (segments[1]) {
    case 'download': return { kind: 'download', upstreamPath: encoded };
    case 'upload': return { kind: 'upload', upstreamPath: encoded };
    case 'eventsource': return { kind: 'eventsource', upstreamPath: encoded };
    default: return { kind: 'other', upstreamPath: encoded };
  }
}

function upstreamOrigin(config: ServerSessionConfig): string {
  return process.env.JMAP_UPSTREAM_ORIGIN || config.issuer;
}

function publicBase(config: ServerSessionConfig, request: NextRequest): string {
  return `${config.publicOrigin}${request.nextUrl.basePath}${MAIL_PREFIX}`;
}

/** Move one URL from the mail server's origin to ours; leave anything else alone. */
function rewriteUrl(value: unknown, from: string, to: string): unknown {
  if (typeof value !== 'string') return value;
  if (value.startsWith(from + '/')) return to + value.slice(from.length);
  if (value.startsWith('/')) return to + value;
  return value;
}

function rewriteSession(body: Record<string, unknown>, from: string, to: string): Record<string, unknown> {
  for (const key of ['apiUrl', 'downloadUrl', 'uploadUrl', 'eventSourceUrl']) {
    if (key in body) body[key] = rewriteUrl(body[key], from, to);
  }
  // WebSocket is not proxied: the client falls back to EventSource and HTTP.
  const strip = (capabilities: unknown) => {
    if (capabilities && typeof capabilities === 'object') delete (capabilities as Record<string, unknown>)['urn:ietf:params:jmap:websocket'];
  };
  strip(body.capabilities);
  const accounts = body.accounts as Record<string, { accountCapabilities?: unknown }> | undefined;
  if (accounts && typeof accounts === 'object') {
    for (const account of Object.values(accounts)) strip(account?.accountCapabilities);
  }
  return body;
}

function json(status: number, body: Record<string, unknown>): NextResponse {
  return NextResponse.json(body, { status, headers: { 'Cache-Control': 'no-store' } });
}

export async function proxyMail(request: NextRequest, segments: string[]): Promise<Response> {
  const config = serverSessionConfig();
  if (!config) return json(404, { error: 'not_configured' });
  // GETs included: a cross-site page has no business reading mail through a
  // victim's cookie, and the Lax cookie would ride along on a top-level GET.
  const fetchSite = request.headers.get('sec-fetch-site');
  if ((fetchSite !== null && fetchSite !== 'same-origin' && fetchSite !== 'none') || !isSameOriginRequest(request)) {
    return json(403, { error: 'cross_origin' });
  }
  const target = route(segments);
  if (!target) return json(404, { error: 'not_found' });

  const sid = readSessionId(request, config);
  let record = sid ? await loadSession(config, sid) : null;
  if (!sid || !record) {
    const response = json(401, { error: 'session_ended' });
    if (sid) clearSessionCookie(response, config);
    return response;
  }

  const method = request.method.toUpperCase();
  const hasBody = method !== 'GET' && method !== 'HEAD';
  const streamBody = hasBody && target.kind === 'upload';
  let buffered: ArrayBuffer | null = null;
  if (hasBody && !streamBody) {
    const declared = Number(request.headers.get('content-length') ?? '0');
    if (declared > MAX_BUFFERED_BODY) return json(413, { error: 'too_large' });
    buffered = await request.arrayBuffer();
    if (buffered.byteLength > MAX_BUFFERED_BODY) return json(413, { error: 'too_large' });
  }

  const from = upstreamOrigin(config);
  const upstreamUrl = `${from}${target.upstreamPath}${request.nextUrl.search}`;
  const headers = new Headers();
  for (const name of FORWARD_REQUEST_HEADERS) {
    const value = request.headers.get(name);
    if (value) headers.set(name, value);
  }

  const send = async (token: string, signal: AbortSignal): Promise<Response> => {
    headers.set('authorization', `Bearer ${token}`);
    return fetch(upstreamUrl, {
      method,
      headers,
      body: streamBody ? request.body : buffered,
      redirect: 'manual',
      cache: 'no-store',
      signal,
      // Required by undici for a streamed request body.
      ...(streamBody ? { duplex: 'half' } : {}),
    } as RequestInit);
  };

  const longLived = target.kind === 'eventsource' || target.kind === 'download' || target.kind === 'upload';
  const signal = longLived ? request.signal : AbortSignal.any([request.signal, AbortSignal.timeout(API_TIMEOUT_MS)]);

  let upstream: Response;
  try {
    let access = await accessToken(config, sid, record);
    if (access.kind === 'ended') {
      const response = json(401, { error: 'session_ended' });
      clearSessionCookie(response, config);
      return response;
    }
    record = access.record;
    upstream = await send(access.accessToken, signal);

    // The token looked valid here and was refused there: renew once and retry,
    // when the body can be sent again. A second refusal ends the session.
    if (upstream.status === 401 && !streamBody) {
      await upstream.body?.cancel().catch(() => {});
      access = await accessToken(config, sid, record, true);
      if (access.kind === 'ended') {
        const response = json(401, { error: 'session_ended' });
        clearSessionCookie(response, config);
        return response;
      }
      upstream = await send(access.accessToken, signal);
      if (upstream.status === 401) {
        await upstream.body?.cancel().catch(() => {});
        logger.warn('Mail server refused a freshly renewed token; ending the session');
        await endSession(config, sid, access.record);
        const response = json(401, { error: 'session_ended' });
        clearSessionCookie(response, config);
        return response;
      }
    }
  } catch (error) {
    if (error instanceof OidcUnavailableError || error instanceof OidcRefusedError) {
      logger.warn('Mail proxy: sign-in provider unavailable', { error: error.message });
      return json(503, { error: 'provider_unavailable' });
    }
    if (request.signal.aborted) return new Response(null, { status: 499 });
    logger.warn('Mail proxy: mail server unreachable', { error: error instanceof Error ? error.message : String(error) });
    return json(503, { error: 'mail_server_unavailable' });
  }

  if (upstream.status >= 300 && upstream.status < 400) {
    // The mail server answers its own JMAP URLs; a redirect off them is not followed.
    await upstream.body?.cancel().catch(() => {});
    return json(502, { error: 'unexpected_redirect' });
  }

  const responseHeaders = new Headers();
  for (const name of FORWARD_RESPONSE_HEADERS) {
    const value = upstream.headers.get(name);
    if (value) responseHeaders.set(name, value);
  }
  responseHeaders.set('X-Content-Type-Options', 'nosniff');
  if (!responseHeaders.has('cache-control')) responseHeaders.set('Cache-Control', 'no-store');

  if (target.kind === 'session' && upstream.ok) {
    const body = (await upstream.json()) as Record<string, unknown>;
    responseHeaders.set('content-type', 'application/json');
    responseHeaders.set('Cache-Control', 'no-store');
    return new Response(JSON.stringify(rewriteSession(body, from, publicBase(config, request))), {
      status: upstream.status,
      headers: responseHeaders,
    });
  }

  if (target.kind === 'download') {
    // A blob is the sender's content. Opened in a tab it runs nothing and reaches nothing.
    responseHeaders.set('Content-Security-Policy', "sandbox; default-src 'none'; img-src data:; style-src 'unsafe-inline'");
  }
  if (target.kind === 'eventsource') {
    responseHeaders.set('Cache-Control', 'no-cache, no-transform');
    responseHeaders.set('X-Accel-Buffering', 'no');
  }

  return new Response(upstream.body, { status: upstream.status, headers: responseHeaders });
}
