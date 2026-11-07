/**
 * SD-WAN sites (M20 §2.5) — GET list (`?overlayId=` filter) + POST create.
 * Mutations audit `site.create` and snapshot section `sdwan`.
 */

import { route } from "@/lib/api/handler";
import { sdwanIdQuerySchema, siteCreateSchema } from "@/lib/validators/sdwan";
import { createSite, listSites } from "@/app/api/v1/sdwan/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "sdwan", querySchema: sdwanIdQuerySchema }, async ({ auth, query }) => {
  return { data: await listSites(auth.tenantId, query.overlayId) };
});

export const POST = route(
  { area: "sdwan", bodySchema: siteCreateSchema, section: "sdwan" },
  async ({ auth, body }) => {
    const created = await createSite(auth.tenantId, body);
    return {
      data: created,
      audit: {
        action: "site.create",
        objectType: "sdwan_site",
        objectId: created.id,
        objectName: created.name,
        after: created,
      },
    };
  },
);
