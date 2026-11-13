/** GET /api/v1/network/routes — live IPv4 route table from /proc/net/route. */

import { route } from "@/lib/api/handler";
import { readRoutes } from "@/lib/host/diagnostics";

export const dynamic = "force-dynamic";

export const GET = route({ area: "network" }, async () => {
  const routes = await readRoutes();
  return { data: routes, meta: { page: 1, limit: routes.length, total: routes.length, totalPages: 1 } };
});
