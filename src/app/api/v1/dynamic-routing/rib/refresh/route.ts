/**
 * RIB refresh (M19 §2.6) — POST syncs the RIB from routing config:
 *   • HOST mode with frr reachable (vtysh + unit active) → REAL read via
 *     `vtysh -c "show ip route json"`, upserted into rib_routes;
 *   • otherwise (simulated plane / frr down / unparseable) → deterministic
 *     regeneration from established BGP sessions, enabled OSPF interfaces and
 *     static routes (unchanged sandbox behavior).
 * Upserts by (tenant, protocol, prefix) and removes stale rows. Audit
 * `rib.refresh` — the result carries `source` so the UI can label the table.
 */

import { route } from "@/lib/api/handler";
import { refreshRib } from "../../internal";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "dynamic_routing", section: "dynamic_routing" },
  async ({ auth }) => {
    const result = await refreshRib(auth.tenantId);
    return {
      data: result,
      audit: {
        action: "rib.refresh",
        objectType: "rib",
        after: result,
      },
    };
  },
);
