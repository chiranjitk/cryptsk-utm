/**
 * GET /api/v1/network/mac-table — derived bridge FDB view (M02 §4 tab 3).
 * Static entries come from DHCP reservations + bridge membership; dynamic
 * entries churn on a 60 s bucket. Filters: ?iface= (exact) ?vlan= ?q=.
 */

import { route } from "@/lib/api/handler";
import { db } from "@/lib/db";
import { macTable } from "@/lib/network/derived";
import { netListQuery } from "@/lib/validators/network";

export const dynamic = "force-dynamic";

export const GET = route({ area: "network", querySchema: netListQuery }, async ({ auth, query }) => {
  let data = await macTable(auth.tenantId);

  if (query.iface) {
    // FDB semantics (M02 §4 tab 3): querying a bridge shows what its ports
    // learned — expand the filter to the bridge's member ifaces.
    const names = new Set([query.iface]);
    const bridge = await db.networkInterface.findFirst({
      where: { tenantId: auth.tenantId, name: query.iface, type: "bridge" },
    });
    if (bridge) {
      let cfg: unknown = {};
      try {
        cfg = JSON.parse(bridge.config);
      } catch {
        cfg = {};
      }
      const members =
        cfg && typeof cfg === "object" && Array.isArray((cfg as Record<string, unknown>).members)
          ? ((cfg as Record<string, unknown>).members as unknown[]).filter(
              (m): m is string => typeof m === "string",
            )
          : [];
      for (const m of members) names.add(m);
    }
    data = data.filter((m) => names.has(m.iface));
  }
  if (query.vlan !== undefined) data = data.filter((m) => m.vlan === query.vlan);
  const q = (query.q ?? "").trim().toLowerCase();
  if (q) data = data.filter((m) => m.mac.toLowerCase().includes(q));

  return {
    data,
    meta: { page: 1, limit: query.limit, total: data.length, totalPages: 1 },
  };
});
