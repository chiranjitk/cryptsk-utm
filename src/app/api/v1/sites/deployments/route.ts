/**
 * /api/v1/sites/deployments — deployment history across the fleet (Phase 4
 * §4.1). GET is server-paginated and filterable by siteId/kind/status; each
 * row carries the pushed/applied timestamps plus the transport result
 * ({applied[], skipped[], errors[]}) with the site name joined in.
 */

import { route } from "@/lib/api/handler";
import { deploymentQuerySchema } from "@/lib/validators/sites";
import { listDeployments } from "@/lib/sites/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "sites", querySchema: deploymentQuerySchema }, async ({ auth, query }) => {
  return listDeployments(auth.tenantId, query);
});
