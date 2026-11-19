/**
 * DNS query log (M06 §3/§5.4) — DERIVED view served from the engine ring
 * buffer: real unbound queries in host mode (ADR-021), generated queries in
 * simulated mode. Rows are not persisted; restarts clear them.
 * Filters: q (domain/client substring), blocked tri-state. Newest first,
 * server-paginated envelope.
 */

import { route } from "@/lib/api/handler";
import { dnsQueryLogQuerySchema } from "@/lib/validators/dns-dhcp";
import { getEngine } from "@/lib/engine";

export const dynamic = "force-dynamic";

export const GET = route({ area: "dns_dhcp", querySchema: dnsQueryLogQuerySchema }, async ({ query, auth }) => {
  const ring = getEngine().dnsRing;
  const q = query.q?.toLowerCase();
  // audit fix H2 — tenant isolation (mirrors tunnel-service engineRowsInLookback,
  // audit fix F-d): ring rows are tenant-tagged; serving the raw ring let a
  // dns_dhcp reader in any tenant see every tenant's queries (domains +
  // client IPs). Filter to the caller's tenant first.
  const filtered = ring.filter((row) => {
    if ((row.tenantId ?? 1) !== auth.tenantId) return false;
    if (query.blocked !== undefined && row.blocked !== query.blocked) return false;
    if (q && !row.domain.toLowerCase().includes(q) && !row.clientIp.includes(q)) return false;
    return true;
  });
  const total = filtered.length;
  const start = (query.page - 1) * query.limit;
  const data = filtered.slice(start, start + query.limit).reverse(); // newest first
  return {
    data,
    meta: { page: query.page, limit: query.limit, total, totalPages: Math.max(1, Math.ceil(total / query.limit)) },
  };
});
