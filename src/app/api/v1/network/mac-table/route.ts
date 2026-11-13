/**
 * GET /api/v1/network/mac-table — bridge FDB view (M02 §4 tab 3). Static
 * entries come from DHCP reservations + bridge membership (config plane);
 * dynamic entries are REAL kernel FDB learns (`bridge fdb show`) when
 * available, deterministic churn simulation otherwise — meta.source marks
 * the dynamic-data origin ("live" | "simulated"). Filters: ?iface= (exact,
 * bridge-aware) ?vlan= ?q=.
 */

import { route } from "@/lib/api/handler";
import { db } from "@/lib/db";
import { macTable } from "@/lib/network/derived";
import { readBridgeFdb } from "@/lib/network/bridge-fdb";
import { netListQuery } from "@/lib/validators/network";

export const dynamic = "force-dynamic";

export const GET = route({ area: "network", querySchema: netListQuery }, async ({ auth, query }) => {
  const derived = await macTable(auth.tenantId);
  const staticRows = derived.filter((m) => m.type === "static");

  // dynamic: real kernel FDB when it reports learned entries, else simulated
  const fdb = await readBridgeFdb().catch(() => ({ available: false, rows: [] }));
  const dynamicRows = fdb.rows
    .filter((r) => r.type === "dynamic")
    .map((r) => ({ mac: r.mac, vlan: r.vlan, iface: r.iface, type: "dynamic" as const, ageSec: 0 }));
  const source = dynamicRows.length > 0 ? "live" : "simulated";
  let data = [...staticRows, ...(dynamicRows.length > 0 ? dynamicRows : derived.filter((m) => m.type === "dynamic"))];

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

  // static first, then by MAC (M02 §4 tab 3)
  data.sort((a, b) => (a.type === b.type ? a.mac.localeCompare(b.mac) : a.type === "static" ? -1 : 1));

  return {
    data,
    meta: { page: 1, limit: query.limit, total: data.length, totalPages: 1, source },
  };
});
