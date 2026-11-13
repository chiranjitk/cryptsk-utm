/**
 * Dynamic routing overview (M19) — one aggregate for the strip cards:
 * BGP session counts, OSPF enabled state + full adjacencies, RIB rows per
 * protocol, BFD profile usage.
 */

import { route } from "@/lib/api/handler";
import { computeOverview } from "@/app/api/v1/dynamic-routing/internal";

export const dynamic = "force-dynamic";

export const GET = route({ area: "dynamic_routing" }, async ({ auth }) => {
  return { data: await computeOverview(auth.tenantId) };
});
