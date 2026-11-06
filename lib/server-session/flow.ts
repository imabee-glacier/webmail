import type { NextRequest, NextResponse } from 'next/server';
import { decryptPayload, encryptPayload } from '@/lib/auth/crypto';
import { isSecureOrigin, type ServerSessionConfig } from './config';

/**
 * What a sign-in has to remember between leaving for the provider and coming
 * back: state, nonce, PKCE verifier, where to land, and whether to stay
 * signed in. Sealed in a short-lived cookie named after its state, so two
 * tabs signing in at once each find their own.
 */
export interface PendingSignIn {
  state: string;
  nonce: string;
  verifier: string;
  returnTo: string;
  persistent: boolean;
  /** Unix seconds. */
  startedAt: number;
}

export const FLOW_TTL_SECONDS = 600;

function flowCookieName(config: ServerSessionConfig, state: string): string {
  return `${isSecureOrigin(config) ? '__Host-' : ''}bmail_flow_${state.slice(0, 16)}`;
}

export function setPendingSignIn(response: NextResponse, config: ServerSessionConfig, pending: PendingSignIn): void {
  response.cookies.set(flowCookieName(config, pending.state), encryptPayload({ ...pending }, 'oidc-flow'), {
    httpOnly: true,
    secure: isSecureOrigin(config),
    // The provider sends the user back with a top-level GET: Lax is sent on it.
    sameSite: 'lax',
    path: '/',
    maxAge: FLOW_TTL_SECONDS,
  });
}

export function takePendingSignIn(
  request: NextRequest,
  response: NextResponse,
  config: ServerSessionConfig,
  state: string,
): PendingSignIn | null {
  if (!/^[A-Za-z0-9_-]{43}$/.test(state)) return null;
  const name = flowCookieName(config, state);
  const sealed = request.cookies.get(name)?.value;
  // One use: whatever happens next, this flow is spent.
  response.cookies.set(name, '', { httpOnly: true, secure: isSecureOrigin(config), sameSite: 'lax', path: '/', maxAge: 0 });
  if (!sealed) return null;
  const payload = decryptPayload(sealed, 'oidc-flow') as unknown as PendingSignIn | null;
  if (!payload || payload.state !== state) return null;
  if (Math.floor(Date.now() / 1000) - payload.startedAt > FLOW_TTL_SECONDS) return null;
  return payload;
}

/**
 * A same-origin path to land on after sign-in, or "/". Only a path: no scheme,
 * no host, no protocol-relative "//", no backslash a browser would read as one.
 */
export function safeReturnTo(value: string | null | undefined): string {
  if (!value || value.length > 2048) return '/';
  if (!value.startsWith('/') || value.startsWith('//') || value.includes('\\')) return '/';
  if (/[\u0000-\u001f]/.test(value)) return '/';
  if (value.startsWith('/api/')) return '/';
  return value;
}
