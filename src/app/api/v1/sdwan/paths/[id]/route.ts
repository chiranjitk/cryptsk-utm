/** Path item (M20 §2.5) — update / delete, audit `path.update|delete`. */

import { route, numericId } from "@/lib/api/handler";
import { pathUpdateSchema } from "@/lib/validators/sdwan";
import { deletePath, updatePath } from "@/app/api/v1/sdwan/service";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "sdwan", bodySchema: pathUpdateSchema, section: "sdwan" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const updated = await updatePath(auth.tenantId, id, body);
    return {
      data: updated,
      audit: {
        action: "path.update",
        objectType: "sdwan_path",
        objectId: id,
        objectName: `${updated.siteName}/${updated.wanInterface}`,
        after: updated,
      },
    };
  },
);

export const DELETE = route({ area: "sdwan", section: "sdwan" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  await deletePath(auth.tenantId, id);
  return { data: { ok: true }, audit: { action: "path.delete", objectType: "sdwan_path", objectId: id } };
});
