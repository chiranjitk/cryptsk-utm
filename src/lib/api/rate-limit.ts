/**
 * In-memory rate limiting (sliding window) — docs/04-API/API_STANDARDS.md §9.
 * Sandbox: local memory cache only, no middleware.
 */

import type { NextRequest } from "next/server";

const buckets = new Map<string, number[]>();

function sweep(now: number) {
  // occasional sweep to avoid unbounded map growth
  if (buckets.size > 10_000) {
    for (const [key, hits] of buckets) {
      const alive = hits.filter((t) => now - t < 120_000);
      if (alive.length === 0) buckets.delete(key);
      else buckets.set(key, alive);
    }
  }
}

/**
 * Consume one token from `key`. Returns { allowed, retryAfterSec }.
 */
export function hit(key: string, limit: number, windowMs = 60_000): { allowed: boolean; retryAfterSec: number } {
  const now = Date.now();
  sweep(now);
  const hits = (buckets.get(key) ?? []).filter((t) => now - t < windowMs);
  if (hits.length >= limit) {
    const retryAfterSec = Math.max(1, Math.ceil((windowMs - (now - hits[0])) / 1000));
    buckets.set(key, hits);
    return { allowed: false, retryAfterSec };
  }
  hits.push(now);
  buckets.set(key, hits);
  return { allowed: true, retryAfterSec: 0 };
}

/**
 * Best-effort client key for PUBLIC-route throttle buckets (login, guest
 * portal). `clientIp()` in handler.ts deliberately never trusts spoofable
 * headers for AUDIT attribution; but with no trusted proxy configured it
 * collapses every unauthenticated caller into one bucket, letting a single
 * guest starve all portal users (cross-user DoS) — audit finding M8.
 *
 * For throttling ONLY, the first XFF hop is honored as a best-effort
 * differentiator. The trade-off is accepted because on these routes the
 * spoofable dimension is never the sole control:
 *   - login: per-username policy lockout (recordLoginFailure) still caps
 *     failures regardless of IP;
 *   - portal redeem/register: voucher codes carry 80 bits of entropy, so
 *     rotating XFF to widen a guessing budget remains infeasible.
 * Audit `sourceIp` keeps using the conservative clientIp() value.
 */
export function publicClientKey(req: NextRequest): string {
  if (process.env.CONSOLE_TRUST_PROXY === "1") {
    const xff = req.headers.get("x-forwarded-for");
    if (xff) return xff.split(",")[0]?.trim() || "127.0.0.1";
    return req.headers.get("x-real-ip") ?? "127.0.0.1";
  }
  // No trusted proxy: honor a present XFF as best-effort bucketing, else the
  // documented coarse-local bucket.
  const xff = req.headers.get("x-forwarded-for");
  const first = xff?.split(",")[0]?.trim();
  return first || "127.0.0.1";
}
