/** Overlay item (M20 §2.5) — update / delete, audit `overlay.update|delete`. */

import { route, numericId } from "@/lib/api/handler";
import { overlayUpdateSchema } from "@/lib/validators/sdwan";
import { deleteOverlay, updateOverlay } from "@/app/api/v1/sdwan/service";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "sdwan", bodySchema: overlayUpdateSchema, section: "sdwan" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const updated = await updateOverlay(auth.tenantId, id, body);
    return {
      data: updated,
      audit: {
        action: "overlay.update",
        objectType: "sdwan_overlay",
        objectId: id,
        objectName: updated.name,
        after: updated,
      },
    };
  },
);

export const DELETE = route({ area: "sdwan", section: "sdwan" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  await deleteOverlay(auth.tenantId, id);
  return { data: { ok: true }, audit: { action: "overlay.delete", objectType: "sdwan_overlay", objectId: id } };
});
