// @vitest-environment node
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { NextRequest } from 'next/server';

/**
 * The whole server-held sign-in against a provider that behaves like the mail
 * server: ES256 ID tokens, PKCE, refresh rotation with one-step retry (a lost
 * response may be redeemed again), reuse detection two steps back, and a JMAP
 * endpoint that checks the bearer.
 */

vi.mock('@/lib/logger', () => ({ logger: { warn: vi.fn(), error: vi.fn(), debug: vi.fn(), info: vi.fn() } }));

const PUBLIC = 'http://localhost:3000';
const CLIENT_ID = 'bmail';
const CLIENT_SECRET = 's3cret/with:odd+chars';

interface Grant { generation: number; pending: boolean; revoked: boolean; sub: string }

const idp = {
  server: null as Server | null,
  origin: '',
  key: null as KeyObject | null,
  jwk: {} as Record<string, unknown>,
  codes: new Map<string, { challenge: string; nonce: string; redirect: string }>(),
  grants: new Map<string, Grant>(),
  tokenCalls: 0,
  refreshCalls: 0,
  revoked: [] as string[],
  validAccess: new Set<string>(),
  /** Tokens the JMAP endpoint refuses once even though valid (resource-side revocation race). */
  refuseOnce: new Set<string>(),
  lastBearer: '',
  nonceOverride: null as string | null,
  issOverride: null as string | null,
  accessTtl: 3600,
};

function b64(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function idToken(claims: Record<string, unknown>): string {
  const header = b64({ alg: 'ES256', kid: 'k1', typ: 'JWT' });
  const body = b64(claims);
  const signature = sign('sha256', Buffer.from(`${header}.${body}`), { key: idp.key!, dsaEncoding: 'ieee-p1363' });
  return `${header}.${body}.${signature.toString('base64url')}`;
}

function issue(grantId: string, generation: number, nonce?: string) {
  const access = `at-${grantId}-${generation}-${Math.random().toString(36).slice(2)}`;
  idp.validAccess.add(access);
  const now = Math.floor(Date.now() / 1000);
  return {
    access_token: access,
    token_type: 'Bearer',
    expires_in: idp.accessTtl,
    refresh_token: `rt.${grantId}.${generation + 1}`,
    id_token: idToken({ iss: idp.origin, aud: CLIENT_ID, sub: 'u1', email: 'pin@appsynergy.io', name: 'Pin', iat: now, exp: now + 300, auth_time: now, amr: ['hwk'], ...(nonce ? { nonce: idp.nonceOverride ?? nonce } : {}) }),
  };
}

async function body(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString('utf8');
}

function send(res: ServerResponse, status: number, value: unknown, headers: Record<string, string> = {}) {
  res.writeHead(status, { 'content-type': 'application/json', ...headers });
  res.end(JSON.stringify(value));
}

async function handle(req: IncomingMessage, res: ServerResponse) {
  const url = new URL(req.url!, idp.origin);
  if (url.pathname === '/.well-known/openid-configuration') {
    return send(res, 200, {
      issuer: idp.origin,
      authorization_endpoint: `${idp.origin}/authorize`,
      token_endpoint: `${idp.origin}/auth/token`,
      jwks_uri: `${idp.origin}/auth/jwks.json`,
      revocation_endpoint: `${idp.origin}/auth/revoke`,
      end_session_endpoint: `${idp.origin}/auth/logout`,
      authorization_response_iss_parameter_supported: true,
    });
  }
  if (url.pathname === '/auth/jwks.json') return send(res, 200, { keys: [idp.jwk] });
  if (url.pathname === '/auth/token') {
    idp.tokenCalls += 1;
    const expected = `Basic ${Buffer.from(`${encodeURIComponent(CLIENT_ID)}:${encodeURIComponent(CLIENT_SECRET)}`).toString('base64')}`;
    if (req.headers.authorization !== expected) return send(res, 401, { error: 'invalid_client' });
    const form = new URLSearchParams(await body(req));
    if (form.get('grant_type') === 'authorization_code') {
      const code = idp.codes.get(form.get('code') ?? '');
      idp.codes.delete(form.get('code') ?? '');
      if (!code || code.redirect !== form.get('redirect_uri')) return send(res, 400, { error: 'invalid_grant' });
      const challenge = createHash('sha256').update(form.get('code_verifier') ?? '').digest('base64url');
      if (challenge !== code.challenge) return send(res, 400, { error: 'invalid_grant' });
      const grantId = `g${idp.grants.size + 1}`;
      idp.grants.set(grantId, { generation: 0, pending: true, revoked: false, sub: 'u1' });
      return send(res, 200, issue(grantId, 0, code.nonce));
    }
    if (form.get('grant_type') === 'refresh_token') {
      idp.refreshCalls += 1;
      const [, grantId, gen] = (form.get('refresh_token') ?? '').split('.');
      const grant = idp.grants.get(grantId);
      const presented = Number(gen);
      if (!grant || grant.revoked) return send(res, 400, { error: 'invalid_grant' });
      // The fork's rotation: presented == stored & pending -> retry; == stored+1 -> commit; older -> reuse, revoke.
      if (presented === grant.generation && grant.pending) return send(res, 200, issue(grantId, grant.generation));
      if (presented === grant.generation + 1 && grant.pending) {
        grant.generation = presented;
        return send(res, 200, issue(grantId, presented));
      }
      if (presented < grant.generation) {
        grant.revoked = true;
        return send(res, 400, { error: 'invalid_grant' });
      }
      return send(res, 400, { error: 'invalid_grant' });
    }
    return send(res, 400, { error: 'unsupported_grant_type' });
  }
  if (url.pathname === '/auth/revoke') {
    const form = new URLSearchParams(await body(req));
    idp.revoked.push(form.get('token') ?? '');
    const [, grantId] = (form.get('token') ?? '').split('.');
    const grant = idp.grants.get(grantId);
    if (grant) grant.revoked = true;
    res.writeHead(200).end();
    return;
  }
  if (url.pathname.startsWith('/jmap')) {
    const bearer = (req.headers.authorization ?? '').replace(/^Bearer /, '');
    idp.lastBearer = bearer;
    if (!idp.validAccess.has(bearer) || idp.refuseOnce.delete(bearer)) return send(res, 401, { status: 401 });
    if (url.pathname === '/jmap/session') {
      return send(res, 200, {
        username: 'pin@appsynergy.io',
        apiUrl: `${idp.origin}/jmap/`,
        downloadUrl: `${idp.origin}/jmap/download/{accountId}/{blobId}/{name}?accept={type}`,
        uploadUrl: `${idp.origin}/jmap/upload/{accountId}/`,
        eventSourceUrl: `${idp.origin}/jmap/eventsource/?types={types}&closeafter={closeafter}&ping={ping}`,
        capabilities: { 'urn:ietf:params:jmap:core': {}, 'urn:ietf:params:jmap:websocket': { url: 'wss://x/jmap/ws' } },
        accounts: { a: { accountCapabilities: { 'urn:ietf:params:jmap:websocket': {} } } },
      });
    }
    if (url.pathname === '/jmap/') return send(res, 200, { echo: await body(req) });
    if (url.pathname.startsWith('/jmap/download/')) {
      res.writeHead(200, { 'content-type': 'text/html', 'set-cookie': 'leak=1' });
      res.end('<script>alert(1)</script>');
      return;
    }
  }
  send(res, 404, {});
}

let dataDir = '';

beforeAll(async () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  idp.key = privateKey;
  idp.jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'ES256', use: 'sig' };
  idp.server = createServer((req, res) => void handle(req, res));
  await new Promise<void>((resolve) => idp.server!.listen(0, '127.0.0.1', resolve));
  const address = idp.server.address() as { port: number };
  idp.origin = `http://127.0.0.1:${address.port}`;
  dataDir = mkdtempSync(path.join(tmpdir(), 'bmail-sessions-'));
  process.env.OIDC_ISSUER = idp.origin;
  process.env.OIDC_CLIENT_ID = CLIENT_ID;
  process.env.OIDC_CLIENT_SECRET = CLIENT_SECRET;
  process.env.PUBLIC_ORIGIN = PUBLIC;
  process.env.SESSIONS_DATA_DIR = dataDir;
  process.env.SESSION_SECRET = 'test-secret-that-is-long-enough-for-aes-256-gcm';
});

afterAll(() => {
  idp.server?.close();
  rmSync(dataDir, { recursive: true, force: true });
});

beforeEach(async () => {
  idp.tokenCalls = 0;
  idp.refreshCalls = 0;
  idp.nonceOverride = null;
  idp.issOverride = null;
  idp.accessTtl = 3600;
  (await import('@/lib/server-session/config')).resetServerSessionConfig();
  (await import('@/lib/server-session/oidc')).resetOidcCaches();
});

function request(pathAndQuery: string, init: { method?: string; cookie?: string; site?: string; body?: string; headers?: Record<string, string> } = {}) {
  return new NextRequest(`${PUBLIC}${pathAndQuery}`, {
    method: init.method ?? 'GET',
    headers: {
      ...(init.cookie ? { cookie: init.cookie } : {}),
      'sec-fetch-site': init.site ?? 'same-origin',
      ...(init.body ? { 'content-type': 'application/json' } : {}),
      ...(init.headers ?? {}),
    },
    body: init.body,
  });
}

function cookiesOf(response: Response): Map<string, string> {
  const out = new Map<string, string>();
  for (const line of response.headers.getSetCookie()) {
    const [pair] = line.split(';');
    const index = pair.indexOf('=');
    out.set(pair.slice(0, index), pair.slice(index + 1));
  }
  return out;
}

/** Walk the sign-in to the end; returns the session cookie header. */
async function signIn(options: { returnTo?: string } = {}): Promise<{ cookie: string; response: Response }> {
  const { GET: signin } = await import('@/app/api/session/signin/route');
  const { GET: callback } = await import('@/app/api/session/callback/route');
  const start = await signin(request(`/api/session/signin?returnTo=${encodeURIComponent(options.returnTo ?? '/inbox')}`));
  expect(start.status).toBe(303);
  const authorize = new URL(start.headers.get('location')!);
  expect(authorize.origin).toBe(idp.origin);
  expect(authorize.searchParams.get('code_challenge_method')).toBe('S256');
  expect(authorize.searchParams.get('redirect_uri')).toBe(`${PUBLIC}/api/session/callback`);
  const flow = [...cookiesOf(start)].find(([name]) => name.startsWith('bmail_flow_'))!;
  expect(flow).toBeTruthy();

  const code = `c${Math.random().toString(36).slice(2)}`;
  idp.codes.set(code, {
    challenge: authorize.searchParams.get('code_challenge')!,
    nonce: authorize.searchParams.get('nonce')!,
    redirect: authorize.searchParams.get('redirect_uri')!,
  });
  const state = authorize.searchParams.get('state')!;
  const done = await callback(request(`/api/session/callback?code=${code}&state=${state}&iss=${encodeURIComponent(idp.issOverride ?? idp.origin)}`, { cookie: `${flow[0]}=${flow[1]}`, site: 'cross-site' }));
  const session = cookiesOf(done).get('bmail_session');
  return { cookie: session ? `bmail_session=${session}` : '', response: done };
}

describe('server-held sign-in', () => {
  it('signs in with PKCE, state and nonce, and lands on returnTo', async () => {
    const { cookie, response } = await signIn({ returnTo: '/mail/folder/inbox?x=1' });
    expect(response.headers.get('location')).toBe(`${PUBLIC}/mail/folder/inbox?x=1`);
    expect(cookie).toMatch(/^bmail_session=[A-Za-z0-9_-]{43}$/);
    const set = response.headers.getSetCookie().find((line) => line.startsWith('bmail_session='))!;
    expect(set).toMatch(/HttpOnly/i);
    expect(set).toMatch(/SameSite=lax/i);
    expect(set).toMatch(/Max-Age=\d+/i);

    const { GET } = await import('@/app/api/session/route');
    const me = await GET(request('/api/session', { cookie }));
    expect(me.status).toBe(200);
    const json = await me.json();
    expect(json.user).toEqual({ username: 'pin@appsynergy.io', name: 'Pin' });
    expect(json.amr).toEqual(['hwk']);
  });

  it('keeps nothing readable at rest', async () => {
    const { cookie } = await signIn();
    const sid = cookie.split('=')[1];
    const files = readdirSync(dataDir).filter((name) => name.endsWith('.session'));
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      expect(file).not.toContain(sid);
      const contents = readFileSync(path.join(dataDir, file), 'utf8');
      expect(contents).not.toContain('rt.');
      expect(contents).not.toContain('at-');
      expect(contents).not.toContain('pin@appsynergy.io');
    }
  });

  it('refuses a callback without its flow cookie, and a replayed one', async () => {
    const { GET: callback } = await import('@/app/api/session/callback/route');
    const forged = await callback(request(`/api/session/callback?code=x&state=${'a'.repeat(43)}&iss=${encodeURIComponent(idp.origin)}`));
    expect(forged.headers.get('location')).toBe(`${PUBLIC}/login?signin_error=expired`);
    expect(cookiesOf(forged).has('bmail_session')).toBe(false);
  });

  it('refuses a wrong nonce and a wrong issuer', async () => {
    idp.nonceOverride = 'not-the-nonce';
    const bad = await signIn();
    expect(bad.cookie).toBe('');
    expect(bad.response.headers.get('location')).toBe(`${PUBLIC}/login?signin_error=failed`);
    idp.nonceOverride = null;

    idp.issOverride = 'https://evil.example';
    const mixed = await signIn();
    expect(mixed.cookie).toBe('');
    expect(mixed.response.headers.get('location')).toBe(`${PUBLIC}/login?signin_error=failed`);
  });

  it('serves the JMAP session with every URL on its own origin and no token', async () => {
    const { cookie } = await signIn();
    const { proxyMail } = await import('@/lib/server-session/jmap-proxy');
    const response = await proxyMail(request('/api/mail/.well-known/jmap', { cookie }), ['.well-known', 'jmap']);
    expect(response.status).toBe(200);
    const session = await response.json();
    expect(session.apiUrl).toBe(`${PUBLIC}/api/mail/jmap/`);
    expect(session.downloadUrl.startsWith(`${PUBLIC}/api/mail/jmap/download/`)).toBe(true);
    expect(session.uploadUrl).toBe(`${PUBLIC}/api/mail/jmap/upload/{accountId}/`);
    expect(session.eventSourceUrl.startsWith(`${PUBLIC}/api/mail/jmap/eventsource/`)).toBe(true);
    expect(session.capabilities['urn:ietf:params:jmap:websocket']).toBeUndefined();
    expect(session.accounts.a.accountCapabilities['urn:ietf:params:jmap:websocket']).toBeUndefined();
    expect(idp.lastBearer.startsWith('at-')).toBe(true);
    expect(JSON.stringify(session)).not.toContain(idp.lastBearer);
  });

  it('sandboxes downloads and drops upstream cookies', async () => {
    const { cookie } = await signIn();
    const { proxyMail } = await import('@/lib/server-session/jmap-proxy');
    const response = await proxyMail(request('/api/mail/jmap/download/a/b/x.html', { cookie }), ['jmap', 'download', 'a', 'b', 'x.html']);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-security-policy')).toContain('sandbox');
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    expect(response.headers.get('set-cookie')).toBeNull();
  });

  it('refuses cross-site requests and paths outside JMAP', async () => {
    const { cookie } = await signIn();
    const { proxyMail } = await import('@/lib/server-session/jmap-proxy');
    const cross = await proxyMail(request('/api/mail/jmap', { cookie, method: 'POST', site: 'cross-site', body: '{}' }), ['jmap']);
    expect(cross.status).toBe(403);
    const crossRead = await proxyMail(request('/api/mail/jmap/session', { cookie, site: 'cross-site' }), ['jmap', 'session']);
    expect(crossRead.status).toBe(403);
    const traversal = await proxyMail(request('/api/mail/x', { cookie }), ['..', 'admin']);
    expect(traversal.status).toBe(404);
    const other = await proxyMail(request('/api/mail/auth/token', { cookie }), ['auth', 'token']);
    expect(other.status).toBe(404);
  });

  it('renews an expiring token once for many concurrent requests, and survives a lost response', async () => {
    idp.accessTtl = 30; // inside the renewal margin: every request wants a renewal
    const { cookie } = await signIn();
    const { proxyMail } = await import('@/lib/server-session/jmap-proxy');
    idp.refreshCalls = 0;
    const responses = await Promise.all(
      Array.from({ length: 8 }, () => proxyMail(request('/api/mail/jmap', { cookie, method: 'POST', body: '{"using":[]}' }), ['jmap'])),
    );
    for (const response of responses) expect(response.status).toBe(200);
    expect(idp.refreshCalls).toBe(1);

    // And a page reload mid-renewal can't hurt: the page holds no token at all.
    const again = await proxyMail(request('/api/mail/jmap', { cookie, method: 'POST', body: '{}' }), ['jmap']);
    expect(again.status).toBe(200);
  });

  it('renews and retries when the mail server refuses a token that looked valid', async () => {
    const { cookie } = await signIn();
    const { proxyMail } = await import('@/lib/server-session/jmap-proxy');
    const first = await proxyMail(request('/api/mail/jmap', { cookie, method: 'POST', body: '{}' }), ['jmap']);
    expect(first.status).toBe(200);
    idp.refuseOnce.add(idp.lastBearer);
    idp.refreshCalls = 0;
    const retried = await proxyMail(request('/api/mail/jmap', { cookie, method: 'POST', body: '{"a":1}' }), ['jmap']);
    expect(retried.status).toBe(200);
    expect(idp.refreshCalls).toBe(1);
    expect((await retried.json()).echo).toBe('{"a":1}');
  });

  it('ends the session on invalid_grant, and only then', async () => {
    const { cookie } = await signIn();
    const sidFiles = () => readdirSync(dataDir).filter((name) => name.endsWith('.session')).length;
    const before = sidFiles();
    for (const grant of idp.grants.values()) grant.revoked = true;
    idp.accessTtl = 30;
    const { proxyMail } = await import('@/lib/server-session/jmap-proxy');
    const { refuseOnce } = idp;
    refuseOnce.clear();
    // Force a renewal by having the mail server refuse the current token.
    idp.validAccess.clear();
    const response = await proxyMail(request('/api/mail/jmap', { cookie, method: 'POST', body: '{}' }), ['jmap']);
    expect(response.status).toBe(401);
    expect((await response.json()).error).toBe('session_ended');
    expect(response.headers.getSetCookie().some((line) => line.startsWith('bmail_session=;') || /bmail_session=; /.test(line) || /bmail_session=;?.*Max-Age=0/i.test(line))).toBe(true);
    expect(sidFiles()).toBe(before - 1);
  });

  it('keeps the session through a provider outage', async () => {
    const { cookie } = await signIn();
    const { proxyMail } = await import('@/lib/server-session/jmap-proxy');
    idp.validAccess.clear(); // the next call needs a renewal
    const saved = process.env.OIDC_CLIENT_SECRET;
    process.env.OIDC_CLIENT_SECRET = 'wrong';
    (await import('@/lib/server-session/config')).resetServerSessionConfig();
    const response = await proxyMail(request('/api/mail/jmap', { cookie, method: 'POST', body: '{}' }), ['jmap']);
    expect(response.status).toBe(503);
    process.env.OIDC_CLIENT_SECRET = saved;
    (await import('@/lib/server-session/config')).resetServerSessionConfig();
    const { GET } = await import('@/app/api/session/route');
    expect((await GET(request('/api/session', { cookie }))).status).toBe(200);
  });

  it('signs out: revokes the grant, removes the session, returns the provider logout', async () => {
    const { cookie } = await signIn();
    const { DELETE, GET } = await import('@/app/api/session/route');
    idp.revoked = [];
    const response = await DELETE(request('/api/session', { cookie, method: 'DELETE' }));
    expect(response.status).toBe(200);
    const { endSessionUrl } = await response.json();
    const logout = new URL(endSessionUrl);
    expect(logout.origin + logout.pathname).toBe(`${idp.origin}/auth/logout`);
    expect(logout.searchParams.get('id_token_hint')).toBeTruthy();
    expect(logout.searchParams.get('post_logout_redirect_uri')).toBe(`${PUBLIC}/`);
    expect(idp.revoked.length).toBe(1);
    expect((await GET(request('/api/session', { cookie }))).status).toBe(401);

    const crossSite = await DELETE(request('/api/session', { cookie, method: 'DELETE', site: 'cross-site' }));
    expect(crossSite.status).toBe(403);
  });
});

describe('safeReturnTo', () => {
  it('admits only same-origin app paths', async () => {
    const { safeReturnTo } = await import('@/lib/server-session/flow');
    expect(safeReturnTo('/mail/folder/inbox?q=1#x')).toBe('/mail/folder/inbox?q=1#x');
    for (const bad of ['//evil.example', '/\\evil.example', 'https://evil.example', 'javascript:alert(1)', '/api/session/signin', '/a\nb', '', null]) {
      expect(safeReturnTo(bad)).toBe('/');
    }
  });
});
