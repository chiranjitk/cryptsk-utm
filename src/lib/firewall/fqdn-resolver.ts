/**
 * FQDN address-object resolver/refresher (spec §1.4).
 *
 * fqdn AddressObjects carry a resolver snapshot (`resolvedIps` JSON array +
 * `resolvedAt`); refreshFqdnObjects re-resolves every fqdn object via
 * node:dns and stamps the snapshot. The PURE core (resolveFqdn, staleness
 * math) lives here next to the DB service, but the generator contract stays
 * the same as everywhere in M03: the nft generator consumes only injected
 * data — it never resolves DNS itself (see nft-gen.ts fqdnObjects input).
 *
 * Failure semantics (deliberate):
 *  • a FAILED refresh leaves the previous snapshot untouched — a transient
 *    DNS blip must not wipe last-known-good enforcement data; the snapshot
 *    ages out via isFqdnStale (the generator skips stale/empty snapshots
 *    with a warning instead of pretending enforcement),
 *  • per-object errors are reported in the RETURNED per-run summary only —
 *    no new table, no timeline noise.
 */

import { promises as dns } from "node:dns";
import { db } from "@/lib/db";

// ── constants (documented windows) ──────────────────────────────────────────

/** Per-lookup timeout — 3s per A/AAAA query (spec §1.4). */
export const FQDN_LOOKUP_TIMEOUT_MS = 3000;
/** Minimum interval between automatic refreshes per object (freshness skip). */
export const FQDN_REFRESH_MIN_INTERVAL_MS = 60_000;
/** Enforcement staleness window: snapshots older than this are skipped by the generator. */
export const FQDN_STALE_MS = 60 * 60_000;

const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
/** Conservative IPv6 shape check — resolver output is trusted for structure, not beauty. */
const IPV6_RE = /^[0-9A-Fa-f:]{2,45}$/;

// ── pure core ───────────────────────────────────────────────────────────────

export interface FqdnResolution {
  hostname: string;
  /** merged unique IPv4 + (optional) IPv6 addresses */
  ips: string[];
  ipv4: string[];
  ipv6: string[];
  /** per-lookup error strings (ENOTFOUND, timeout, …) — never thrown */
  errors: string[];
  durationMs: number;
}

export interface ResolveFqdnOptions {
  /** also resolve AAAA records (default false — sets are ipv4_addr today) */
  ipv6?: boolean;
  /** per-lookup timeout override (tests inject small values) */
  timeoutMs?: number;
}

function withTimeout<T>(p: Promise<T>, timeoutMs: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${timeoutMs}ms`)), timeoutMs);
    timer.unref?.();
  });
  return Promise.race([p, timeout]).finally(() => clearTimeout(timer));
}

/**
 * Resolve one hostname: node:dns resolve4 (always) + resolve6 (when wanted),
 * each with a hard 3s timeout (default). Never throws — failures land in
 * `errors` and the caller decides (empty ips ⇒ failed refresh).
 */
export async function resolveFqdn(hostname: string, opts: ResolveFqdnOptions = {}): Promise<FqdnResolution> {
  const timeoutMs = Math.max(1, opts.timeoutMs ?? FQDN_LOOKUP_TIMEOUT_MS);
  const started = Date.now();
  const errors: string[] = [];
  const ipv4: string[] = [];
  const ipv6: string[] = [];

  const v4 = withTimeout(dns.resolve4(hostname), timeoutMs, `${hostname} A`).then(
    (addrs) => {
      for (const a of addrs ?? []) if (IPV4_RE.test(a) && !ipv4.includes(a)) ipv4.push(a);
    },
    (err: unknown) => {
      errors.push(`${hostname} A: ${err instanceof Error ? err.message : String(err)}`);
    },
  );

  const v6 = opts.ipv6
    ? withTimeout(dns.resolve6(hostname), timeoutMs, `${hostname} AAAA`).then(
        (addrs) => {
          for (const a of addrs ?? []) if (IPV6_RE.test(a) && a.includes(":") && !ipv6.includes(a)) ipv6.push(a);
        },
        (err: unknown) => {
          errors.push(`${hostname} AAAA: ${err instanceof Error ? err.message : String(err)}`);
        },
      )
    : Promise.resolve();

  await Promise.all([v4, v6]);
  return {
    hostname,
    ips: [...ipv4, ...ipv6],
    ipv4,
    ipv6,
    errors,
    durationMs: Date.now() - started,
  };
}

/** True when there is no snapshot or it is older than the enforcement window. */
export function isFqdnStale(resolvedAt: Date | null, now: number = Date.now()): boolean {
  if (!resolvedAt) return true;
  return now - resolvedAt.getTime() > FQDN_STALE_MS;
}

// ── DB service ──────────────────────────────────────────────────────────────

export type FqdnObjectStatus = "resolved" | "failed" | "unchanged";

export interface FqdnRefreshEntry {
  id: number;
  name: string;
  hostname: string;
  status: FqdnObjectStatus;
  ipCount: number;
  error?: string;
}

export interface FqdnRefreshResult {
  ranAt: string;
  durationMs: number;
  resolved: number;
  failed: number;
  /** objects skipped because their snapshot is fresher than the 60s window */
  unchanged: number;
  /** per-run summary — kept in the response, NOT persisted to a table */
  results: FqdnRefreshEntry[];
}

export interface RefreshFqdnOptions {
  /** re-resolve even when the snapshot is <60s old */
  force?: boolean;
  /** store IPv6 addresses too (generator still enforces IPv4 only) */
  ipv6?: boolean;
}

/**
 * Refresh every fqdn address object of the tenant: resolve → stamp
 * resolvedIps/resolvedAt. Skips objects refreshed <60s ago unless force.
 * Failed resolutions keep the previous snapshot and report the error in the
 * per-run summary only.
 */
export async function refreshFqdnObjects(
  tenantId: number,
  opts: RefreshFqdnOptions = {},
): Promise<FqdnRefreshResult> {
  const started = Date.now();
  const rows = await db.addressObject.findMany({
    where: { tenantId, type: "fqdn" },
    orderBy: { name: "asc" },
  });

  const results: FqdnRefreshEntry[] = [];
  let resolved = 0;
  let failed = 0;
  let unchanged = 0;

  await Promise.all(
    rows.map(async (row) => {
      const fresh =
        !opts.force && row.resolvedAt !== null && Date.now() - row.resolvedAt.getTime() < FQDN_REFRESH_MIN_INTERVAL_MS;
      if (fresh) {
        unchanged += 1;
        results.push({
          id: row.id,
          name: row.name,
          hostname: row.value,
          status: "unchanged",
          ipCount: safeCount(row.resolvedIps),
        });
        return;
      }

      const outcome = await resolveFqdn(row.value, { ipv6: opts.ipv6 });
      if (outcome.ips.length === 0) {
        failed += 1;
        results.push({
          id: row.id,
          name: row.name,
          hostname: row.value,
          status: "failed",
          ipCount: safeCount(row.resolvedIps),
          error: outcome.errors.join("; ") || "no addresses returned",
        });
        return;
      }

      await db.addressObject.update({
        where: { id: row.id },
        data: { resolvedIps: JSON.stringify(outcome.ips), resolvedAt: new Date() },
      });
      resolved += 1;
      results.push({
        id: row.id,
        name: row.name,
        hostname: row.value,
        status: "resolved",
        ipCount: outcome.ips.length,
      });
    }),
  );

  results.sort((a, b) => a.name.localeCompare(b.name) || a.id - b.id);
  return {
    ranAt: new Date(started).toISOString(),
    durationMs: Date.now() - started,
    resolved,
    failed,
    unchanged,
    results,
  };
}

function safeCount(raw: string): number {
  try {
    const v = JSON.parse(raw);
    return Array.isArray(v) ? v.length : 0;
  } catch {
    return 0;
  }
}
