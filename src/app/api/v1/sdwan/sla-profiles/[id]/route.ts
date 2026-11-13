/** SLA profile item (M20 §2.5) — update / delete, audit `sla_profile.update|delete`. */

import { route, numericId } from "@/lib/api/handler";
import { slaProfileUpdateSchema } from "@/lib/validators/sdwan";
import { deleteSlaProfile, updateSlaProfile } from "@/app/api/v1/sdwan/service";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "sdwan", bodySchema: slaProfileUpdateSchema, section: "sdwan" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const updated = await updateSlaProfile(auth.tenantId, id, body);
    return {
      data: updated,
      audit: {
        action: "sla_profile.update",
        objectType: "sla_profile",
        objectId: id,
        objectName: updated.name,
        after: updated,
      },
    };
  },
);

export const DELETE = route({ area: "sdwan", section: "sdwan" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  await deleteSlaProfile(auth.tenantId, id);
  return { data: { ok: true }, audit: { action: "sla_profile.delete", objectType: "sla_profile", objectId: id } };
});
