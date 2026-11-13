/**
 * GET /api/v1/network/lldp-neighbors — LLDP neighbor table (M02 §4 tab 2).
 * REAL `lldpctl` (lldpd) data when the daemon is installed, deterministic
 * churn simulation otherwise — meta.source marks the origin honestly
 * ("live" | "simulated"). Filters: ?iface= ?q=. Auto-refresh 10 s in the UI.
 */

import { route } from "@/lib/api/handler";
import { lldpNeighbors } from "@/lib/network/derived";
import { readLldpNeighborsReal } from "@/lib/network/lldp-ctl";
import { netListQuery } from "@/lib/validators/network";

export const dynamic = "force-dynamic";

export const GET = route({ area: "network", querySchema: netListQuery }, async ({ auth, query }) => {
  const real = await readLldpNeighborsReal().catch(() => ({ available: false, rows: [] }));
  let data = real.available
    ? real.rows.map((r) => ({ ...r }))
    : await lldpNeighbors(auth.tenantId);
  const source = real.available ? "live" : "simulated";

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
    meta: { page: 1, limit: query.limit, total: data.length, totalPages: 1, source },
  };
});
