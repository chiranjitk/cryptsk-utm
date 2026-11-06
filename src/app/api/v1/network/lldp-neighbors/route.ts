/**
 * GET /api/v1/network/lldp-neighbors — derived LLDP neighbor table (M02 §4
 * tab 2, live view; auto-refresh 10 s in the UI). Filters: ?iface= ?q=.
 * Not persisted — churned deterministically every 30 s (SIMULATION_LAYER §6).
 */

import { route } from "@/lib/api/handler";
import { lldpNeighbors } from "@/lib/network/derived";
import { netListQuery } from "@/lib/validators/network";

export const dynamic = "force-dynamic";

export const GET = route({ area: "network", querySchema: netListQuery }, async ({ auth, query }) => {
  let data = await lldpNeighbors(auth.tenantId);

  if (query.iface) data = data.filter((n) => n.localIface === query.iface);
  const q = (query.q ?? "").trim().toLowerCase();
  if (q) {
    data = data.filter(
      (n) =>
        n.localIface.toLowerCase().includes(q) ||
        n.systemName.toLowerCase().includes(q) ||
        n.chassisId.toLowerCase().includes(q),
    );
  }

  return {
    data,
    meta: { page: 1, limit: query.limit, total: data.length, totalPages: 1 },
  };
});
