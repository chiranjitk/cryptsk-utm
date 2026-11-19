/**
 * /api/v1/sites — managed site fleet list + creation (Phase 4 §4.1).
 * GET is server-paginated with status/role filters and a q search over
 * name/region/endpoint; POST registers a new UTM instance under this central
 * console. RBAC lives in the "sites" capability area (network_admins manage).
 */

import { route } from "@/lib/api/handler";
import { siteCreateSchema, siteQuerySchema } from "@/lib/validators/sites";
import { createSite, listSites } from "@/lib/sites/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "sites", querySchema: siteQuerySchema }, async ({ auth, query }) => {
  return listSites(auth.tenantId, query);
});

export const POST = route(
  { area: "sites", bodySchema: siteCreateSchema },
  async ({ auth, body }) => {
    const created = await createSite(auth.tenantId, body, auth.username ?? "system");
    return {
      data: created,
      audit: {
        action: "site.create",
        objectType: "site",
        objectId: created.id,
        objectName: created.name,
        after: created,
      },
    };
  },
);
