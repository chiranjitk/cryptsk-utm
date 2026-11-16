/**
 * GET /api/v1/dynamic-routing/os — live FRR integration status: tool
 * availability, frr service state, live vs rendered conf hash, drift reasons,
 * daemon-set match, console state file, and a rendered conf preview. When frr
 * is reachable the BGP neighbor / OSPF adjacency states from
 * `vtysh -c "show bgp summary json"` / `show ip ospf neighbor json` are
 * written back onto the BgpNeighbor / OspfInterface rows (real session truth
 * — see simulatedSessionNote for the session start/stop buttons).
 * Read-only, area `dynamic_routing`. Sandbox: available=false, honest.
 */

import { route } from "@/lib/api/handler";
import { readDynamicRoutingOsStatus } from "@/lib/dynamic-routing/os-service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "dynamic_routing" }, async ({ auth }) => {
  return { data: await readDynamicRoutingOsStatus(auth.tenantId) };
});
