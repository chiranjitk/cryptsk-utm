/**
 * GET /api/v1/network/app-catalog — static nDPI app-label catalog (feeds the
 * Rules editor Applications picker; ENDPOINTS §3). Read floor soc_analyst.
 */

import { route } from "@/lib/api/handler";
import { APP_CATALOG } from "@/lib/firewall/app-catalog";

export const dynamic = "force-dynamic";

export const GET = route({ area: "network" }, async () => {
  return { data: { apps: APP_CATALOG, total: APP_CATALOG.length } };
});
