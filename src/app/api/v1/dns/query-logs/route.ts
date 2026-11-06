/**
 * DNS query log (M06 §3/§5.4) — DERIVED view served straight from the
 * MockEngine ring buffer. Rows are not persisted; restarts and --reset clear
 * them (SIMULATION_LAYER §6). Filters: q (domain/client substring), blocked
 * tri-state. Newest first, server-paginated envelope.
 */

import { route } from "@/lib/api/handler";
import { dnsQueryLogQuerySchema } from "@/lib/validators/dns-dhcp";
import { getMockEngine } from "@/lib/engine/mock-engine";

export const dynamic = "force-dynamic";

export const GET = route({ area: "dns_dhcp", querySchema: dnsQueryLogQuerySchema }, async ({ query }) => {
  const ring = getMockEngine().dnsRing;
  const q = query.q?.toLowerCase();
  const filtered = ring.filter((row) => {
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
