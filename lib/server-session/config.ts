import { readFileEnv } from '@/lib/read-file-env';

/**
 * Server-held sign-in: the webmail is a confidential OpenID Connect client of
 * the mail server, and the browser holds nothing but an opaque session cookie.
 *
 * The mail server is the identity provider. It runs the sign-in itself, with
 * passkeys on its own origin, and this app never sees a password. Tokens stay
 * on this server; the browser reaches JMAP through the same-origin proxy under
 * /api/mail, so there is no bearer for script to read and no CORS to open.
 *
 * Enabled when OIDC_ISSUER, OIDC_CLIENT_ID and a client secret are all set.
 * Everything else has a default.
 */
export interface ServerSessionConfig {
  /** Exact issuer, e.g. https://mail.example.org. Discovery must echo it. */
  issuer: string;
  clientId: string;
  clientSecret: string;
  /** This app's public origin, e.g. https://webmail.example.org. */
  publicOrigin: string;
  /** Requested on every sign-in. */
  scopes: string;
  /** "Stay signed in": idle limit, renewed by use. */
  persistentIdleSeconds: number;
  /** Hard ceiling on any session, however active. */
  absoluteSeconds: number;
  /** A session without "stay signed in": idle limit. Its cookie also ends with the browser. */
  transientIdleSeconds: number;
}

const DEFAULT_SCOPES = 'openid email profile offline_access mail contacts calendars files';

function seconds(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const value = Number.parseInt(raw, 10);
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

function origin(value: string): string | null {
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopback(url.hostname))) return null;
    return url.origin;
  } catch {
    return null;
  }
}

function isLoopback(host: string): boolean {
  return host === 'localhost' || host === '127.0.0.1' || host === '[::1]';
}

let cached: ServerSessionConfig | null | undefined;

/** The configuration, or null when server-held sign-in is not set up. */
export function serverSessionConfig(): ServerSessionConfig | null {
  if (cached !== undefined) return cached;
  const issuer = origin(process.env.OIDC_ISSUER ?? '');
  const clientId = process.env.OIDC_CLIENT_ID ?? '';
  const clientSecret = process.env.OIDC_CLIENT_SECRET || readFileEnv(process.env.OIDC_CLIENT_SECRET_FILE) || '';
  const publicOrigin = origin(process.env.PUBLIC_ORIGIN ?? '');
  if (!issuer || !clientId || !clientSecret || !publicOrigin) {
    cached = null;
    return cached;
  }
  const day = 86_400;
  cached = {
    issuer,
    clientId,
    clientSecret,
    publicOrigin,
    scopes: process.env.OIDC_SCOPES || DEFAULT_SCOPES,
    persistentIdleSeconds: seconds('SESSION_IDLE_SECONDS', 30 * day),
    absoluteSeconds: seconds('SESSION_ABSOLUTE_SECONDS', 90 * day),
    transientIdleSeconds: seconds('SESSION_TRANSIENT_IDLE_SECONDS', 12 * 3600),
  };
  return cached;
}

export function isServerSessionEnabled(): boolean {
  return serverSessionConfig() !== null;
}

/** Cookies get the __Host- prefix whenever the app is served over HTTPS. */
export function isSecureOrigin(config: ServerSessionConfig): boolean {
  return config.publicOrigin.startsWith('https:');
}

/** For tests. */
export function resetServerSessionConfig(): void {
  cached = undefined;
}
