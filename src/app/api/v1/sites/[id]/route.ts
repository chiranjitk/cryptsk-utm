/**
 * /api/v1/sites/[id] — single managed site: GET detail, PATCH partial update
 * (endpoint/version/status/role/limits/notes), DELETE (removes the site plus
 * its deployment history — see deleteSite in the service).
 */

import { route, numericId } from "@/lib/api/handler";
import { siteUpdateSchema } from "@/lib/validators/sites";
import { deleteSite, getSite, updateSite } from "@/lib/sites/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "sites" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  return { data: await getSite(auth.tenantId, id) };
});

export const PATCH = route(
  { area: "sites", bodySchema: siteUpdateSchema },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const updated = await updateSite(auth.tenantId, id, body);
    return {
      data: updated,
      audit: {
        action: "site.update",
        objectType: "site",
        objectId: id,
        objectName: updated.name,
        after: updated,
      },
    };
  },
);

export const DELETE = route({ area: "sites" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  const deleted = await deleteSite(auth.tenantId, id);
  return { data: deleted, audit: { action: "site.delete", objectType: "site", objectId: id } };
});
