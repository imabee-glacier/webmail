import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { decryptPayload, encryptPayload } from '@/lib/auth/crypto';

/**
 * Server-held sessions, one sealed file per session.
 *
 * The file is named by the SHA-256 of the cookie value, never the value
 * itself, and its contents are AES-256-GCM under the session secret, bound to
 * this purpose. Reading the directory gives neither a usable cookie nor a
 * token. Writes go to a temporary file and are renamed into place, so a crash
 * mid-write leaves the previous record, not half of one.
 */
export interface SessionRecord {
  v: 1;
  sub: string;
  /** The mail address the account signs in as. */
  username: string;
  name: string;
  /** Unix seconds. */
  createdAt: number;
  lastSeenAt: number;
  /** Absolute end, whatever the activity. */
  expiresAt: number;
  /** "Stay signed in": a persistent cookie and the long idle limit. */
  persistent: boolean;
  accessToken: string;
  accessExpiresAt: number;
  refreshToken: string | null;
  idToken: string | null;
  /** When the user last proved who they are at the provider (auth_time), if it says. */
  authTime: number | null;
  /** How they did it (amr), if the provider says. */
  amr: string[];
}

function sessionDir(): string {
  return process.env.SESSIONS_DATA_DIR || path.join(process.cwd(), 'data', 'sessions');
}

export function sessionKey(sid: string): string {
  return createHash('sha256').update(sid, 'utf8').digest('hex');
}

function fileFor(sid: string): string {
  return path.join(sessionDir(), `${sessionKey(sid)}.session`);
}

let ensured: Promise<void> | null = null;
function ensureDir(): Promise<void> {
  ensured ??= fs.mkdir(sessionDir(), { recursive: true, mode: 0o700 }).then(() => undefined);
  return ensured;
}

export async function readSession(sid: string): Promise<SessionRecord | null> {
  let sealed: string;
  try {
    sealed = await fs.readFile(fileFor(sid), 'utf8');
  } catch {
    return null;
  }
  const payload = decryptPayload(sealed, 'server-session');
  if (!payload || payload.v !== 1) return null;
  return payload as unknown as SessionRecord;
}

export async function writeSession(sid: string, record: SessionRecord): Promise<void> {
  await ensureDir();
  const target = fileFor(sid);
  const temporary = `${target}.${process.pid}.${Date.now()}.tmp`;
  await fs.writeFile(temporary, encryptPayload({ ...record }, 'server-session'), { mode: 0o600 });
  await fs.rename(temporary, target);
}

export async function deleteSession(sid: string): Promise<void> {
  await fs.rm(fileFor(sid), { force: true });
}

/**
 * Remove sessions past their end. Files are opened only when their mtime says
 * they may be stale; a record's lastSeenAt is written at most every few
 * minutes, so mtime tracks it closely enough to skip the live ones unread.
 */
export async function sweepSessions(idleSeconds: { persistent: number; transient: number }): Promise<number> {
  let names: string[];
  try {
    names = await fs.readdir(sessionDir());
  } catch {
    return 0;
  }
  const now = Date.now() / 1000;
  const shortest = Math.min(idleSeconds.persistent, idleSeconds.transient);
  let removed = 0;
  for (const name of names) {
    const file = path.join(sessionDir(), name);
    if (name.endsWith('.tmp')) {
      const stat = await fs.stat(file).catch(() => null);
      if (stat && now - stat.mtimeMs / 1000 > 3600) await fs.rm(file, { force: true });
      continue;
    }
    if (!name.endsWith('.session')) continue;
    const stat = await fs.stat(file).catch(() => null);
    if (!stat || now - stat.mtimeMs / 1000 < shortest) continue;
    const sealed = await fs.readFile(file, 'utf8').catch(() => null);
    const record = sealed ? (decryptPayload(sealed, 'server-session') as unknown as SessionRecord | null) : null;
    if (!record || isExpired(record, idleSeconds, now)) {
      await fs.rm(file, { force: true });
      removed += 1;
    }
  }
  return removed;
}

export function isExpired(
  record: SessionRecord,
  idleSeconds: { persistent: number; transient: number },
  now = Date.now() / 1000,
): boolean {
  if (now >= record.expiresAt) return true;
  const idle = record.persistent ? idleSeconds.persistent : idleSeconds.transient;
  return now - record.lastSeenAt >= idle;
}
