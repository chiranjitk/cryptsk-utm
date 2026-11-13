/** Site item (M20 §2.5) — update / delete (cascades its paths), audit `site.update|delete`. */

import { route, numericId } from "@/lib/api/handler";
import { siteUpdateSchema } from "@/lib/validators/sdwan";
import { deleteSite, updateSite } from "@/app/api/v1/sdwan/service";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "sdwan", bodySchema: siteUpdateSchema, section: "sdwan" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const updated = await updateSite(auth.tenantId, id, body);
    return {
      data: updated,
      audit: {
        action: "site.update",
        objectType: "sdwan_site",
        objectId: id,
        objectName: updated.name,
        after: updated,
      },
    };
  },
);

export const DELETE = route({ area: "sdwan", section: "sdwan" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  await deleteSite(auth.tenantId, id);
  return { data: { ok: true }, audit: { action: "site.delete", objectType: "sdwan_site", objectId: id } };
});
