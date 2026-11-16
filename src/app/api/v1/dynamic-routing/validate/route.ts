/**
 * POST /api/v1/dynamic-routing/validate — render the console routing config
 * into frr.conf and run `vtysh -C -f <stage>` (parse WITHOUT applying —
 * frr-reload.py is NOT installed on the appliance) on a TEMP file. Nothing on
 * the appliance is modified: no /etc write, no service restart. Sandbox
 * (no vtysh / simulated data plane) returns honest { available:false } with
 * the rendered conf attached for preview.
 */

import { route } from "@/lib/api/handler";
import { validateDynamicRouting } from "@/lib/dynamic-routing/os-service";

export const dynamic = "force-dynamic";

export const POST = route({ area: "dynamic_routing", section: "dynamic_routing" }, async ({ auth }) => {
  return { data: await validateDynamicRouting(auth.tenantId) };
});
