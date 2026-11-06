import type { NextRequest } from 'next/server';
import { proxyMail } from '@/lib/server-session/jmap-proxy';

/** Same-origin JMAP for a server-held sign-in (lib/server-session/jmap-proxy.ts). */
export const dynamic = 'force-dynamic';

type Context = { params: Promise<{ path: string[] }> };

async function handle(request: NextRequest, context: Context): Promise<Response> {
  const { path } = await context.params;
  return proxyMail(request, path);
}

export const GET = handle;
export const POST = handle;
export const PUT = handle;
export const PATCH = handle;
export const DELETE = handle;
