/**
 * In-memory rate limiting (sliding window) — docs/04-API/API_STANDARDS.md §9.
 * Sandbox: local memory cache only, no middleware.
 */

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
