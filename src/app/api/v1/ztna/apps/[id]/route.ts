/**
 * /api/v1/ztna/apps/[id] — single ZTNA application: read, update, delete
 * (delete is refused while access policies still reference the app).
 */

import { route, numericId } from "@/lib/api/handler";
import { ztnaAppUpdateSchema } from "@/lib/validators/ztna";
import { deleteApp, getApp, updateApp } from "@/lib/ztna/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "ztna" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  return { data: await getApp(auth.tenantId, id) };
});

export const PATCH = route(
  { area: "ztna", bodySchema: ztnaAppUpdateSchema, section: "ztna" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const updated = await updateApp(auth.tenantId, id, body);
    return {
      data: updated,
      audit: {
        action: "ztna.app.update",
        objectType: "ztna_application",
        objectId: id,
        objectName: updated.name,
        after: updated,
      },
    };
  },
);

export const DELETE = route({ area: "ztna", section: "ztna" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  const deleted = await deleteApp(auth.tenantId, id);
  return { data: deleted, audit: { action: "ztna.app.delete", objectType: "ztna_application", objectId: id } };
});
