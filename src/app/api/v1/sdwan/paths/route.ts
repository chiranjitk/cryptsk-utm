/**
 * SD-WAN paths (M20 §2.5) — GET list (`?siteId=` filter). Creation happens
 * under /sites/[siteId]/paths so the WAN link is always scoped to a site.
 */

import { route } from "@/lib/api/handler";
import { pathsQuerySchema } from "@/lib/validators/sdwan";
import { listPaths } from "@/app/api/v1/sdwan/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "sdwan", querySchema: pathsQuerySchema }, async ({ auth, query }) => {
  return { data: await listPaths(auth.tenantId, query.siteId) };
});
