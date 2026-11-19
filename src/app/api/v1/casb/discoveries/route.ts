/**
 * GET /api/v1/casb/discoveries — paginated observed-SaaS usage per client
 * (Phase 4 §4.3). Filters: verdict (sanctioned|shadow|unknown), category
 * (catalog-side attribute of the matched app) and a free-text q over
 * clientIp/appHint.
 */

import { route } from "@/lib/api/handler";
import { discoveryQuerySchema } from "@/lib/validators/casb";
import { listDiscoveries } from "@/lib/casb/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "casb", querySchema: discoveryQuerySchema }, async ({ auth, query }) => {
  return listDiscoveries(auth.tenantId, query);
});
