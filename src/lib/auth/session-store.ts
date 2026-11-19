/**
 * Server-side session registry — AuthSession (schema §7) + audit fix F-c #1.
 *
 * Every signed JWT carries a `jti` that is registered here at login. The
 * authenticate path (./session.ts) consults this store after signature
 * verification: revoked / expired / MISSING rows mean 401 (fail closed —
 * tokens minted before the registry existed no longer authenticate).
 *
 * In-process cache: Map<jti, {ok, userId, cachedAt}> with a 60 s TTL so a
 * warm request path does not hit SQLite per request. Revocation removes the
 * cache entry immediately (same process); entries never outlive the TTL, so
 * worst case a revocation from another process takes ≤ 60 s to propagate
 * (single-process sandbox: immediate).
 */

import { db } from "@/lib/db";

const CACHE_TTL_MS = 60_000;
const CACHE_MAX = 10_000;

type CacheEntry = { ok: boolean; userId: number; cachedAt: number };

const cache = new Map<string, CacheEntry>();

function cacheGet(jti: string): CacheEntry | undefined {
  const entry = cache.get(jti);
  if (!entry) return undefined;
  if (Date.now() - entry.cachedAt > CACHE_TTL_MS) {
    cache.delete(jti);
    return undefined;
  }
  return entry;
}

function cacheSet(jti: string, ok: boolean, userId: number): void {
  if (cache.size >= CACHE_MAX) {
    // cheap pruning: drop stale entries first, then oldest cache hits
    const now = Date.now();
    for (const [k, v] of cache) {
      if (now - v.cachedAt > CACHE_TTL_MS) cache.delete(k);
    }
    if (cache.size >= CACHE_MAX) {
      const oldest = [...cache.entries()].sort((a, b) => a[1].cachedAt - b[1].cachedAt).slice(0, cache.size - CACHE_MAX + 1);
      for (const [k] of oldest) cache.delete(k);
    }
  }
  cache.set(jti, { ok, userId, cachedAt: Date.now() });
}

/** Register a freshly minted session (login route, after signSession). */
export async function createAuthSession(input: {
  jti: string;
  userId: number;
  tenantId: number;
  ip: string;
  userAgent: string;
  expiresAt: Date;
}): Promise<void> {
  await db.authSession.create({
    data: {
      jti: input.jti,
      userId: input.userId,
      tenantId: input.tenantId,
      ip: input.ip,
      userAgent: input.userAgent,
      expiresAt: input.expiresAt,
    },
  });
  cacheSet(input.jti, true, input.userId);
}

/**
 * Is the jti registered, unrevoked and unexpired? (authenticate path —
 * called after the JWT signature already verified.)
 */
export async function isSessionActive(jti: string): Promise<boolean> {
  const hit = cacheGet(jti);
  if (hit) return hit.ok;
  let ok = false;
  let userId = -1;
  const row = await db.authSession.findUnique({ where: { jti } }).catch(() => null);
  if (row) {
    ok = row.revokedAt === null && row.expiresAt.getTime() > Date.now();
    userId = row.userId;
  }
  cacheSet(jti, ok, userId); // negatives are cached too (missing/revoked rows are stable)
  return ok;
}

/** Revoke one session by jti (logout) — signature must be verified upstream. */
export async function revokeSessionByJti(jti: string): Promise<void> {
  cache.delete(jti);
  await db.authSession.updateMany({ where: { jti, revokedAt: null }, data: { revokedAt: new Date() } });
}

/**
 * Revoke ALL active sessions for a user (lifecycle hook: isActive → false,
 * role change, password change/delete — audit fix F-c #1; also drops their
 * cache entries so the next request re-reads the revoked rows).
 */
export async function revokeAllUserSessions(userId: number): Promise<void> {
  const active = await db.authSession.findMany({ where: { userId, revokedAt: null }, select: { jti: true } });
  for (const { jti } of active) cache.delete(jti);
  if (active.length > 0) {
    await db.authSession.updateMany({ where: { userId, revokedAt: null }, data: { revokedAt: new Date() } });
  }
}

/**
 * Concurrent-session cap (audit fix F-c #9, auth policy
 * `sessionLimits.maxConcurrentPerUser`, default 4): count active sessions
 * (revokedAt null, expiresAt > now) and revoke the OLDEST beyond cap − 1 so
 * the about-to-be-created session stays within the cap.
 */
export async function enforceConcurrentSessionCap(userId: number, cap: number | undefined | null): Promise<void> {
  if (cap === undefined || cap === null || !Number.isFinite(cap) || cap < 1) return;
  const active = await db.authSession.findMany({
    where: { userId, revokedAt: null, expiresAt: { gt: new Date() } },
    orderBy: [{ createdAt: "asc" }, { id: "asc" }],
    select: { id: true, jti: true },
  });
  const allowed = Math.max(0, Math.floor(cap) - 1);
  if (active.length <= allowed) return;
  const excess = active.slice(0, active.length - allowed);
  for (const s of excess) cache.delete(s.jti);
  await db.authSession.updateMany({ where: { id: { in: excess.map((s) => s.id) } }, data: { revokedAt: new Date() } });
}
