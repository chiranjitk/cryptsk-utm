/**
 * RIB refresh (M19 §2.6) — POST regenerates the simulated FRR RIB from
 * enabled config: established BGP sessions (2-6 prefixes each), enabled OSPF
 * interfaces (one 10.x.x.0/24 per area, metric = cost) and static routes
 * (gateway → static, interface-only → connected). Upserts by
 * (tenant, protocol, prefix) and removes stale rows. Audit `rib.refresh`.
 */

import { route } from "@/lib/api/handler";
import { regenerateRib } from "../../internal";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "dynamic_routing", section: "dynamic_routing" },
  async ({ auth }) => {
    const result = await regenerateRib(auth.tenantId);
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
