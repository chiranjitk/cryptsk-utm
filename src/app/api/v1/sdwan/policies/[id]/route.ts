/** Policy item (M20 §2.5) — update / delete, audit `policy.update|delete`. */

import { route } from "@/lib/api/handler";
import { policyUpdateSchema } from "@/lib/validators/sdwan";
import { deletePolicy, updatePolicy } from "@/app/api/v1/sdwan/service";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "sdwan", bodySchema: policyUpdateSchema, section: "sdwan" },
  async ({ auth, body, params }) => {
    const id = Number(params.id);
    const updated = await updatePolicy(auth.tenantId, id, body);
    return {
      data: updated,
      audit: {
        action: "policy.update",
        objectType: "sdwan_policy",
        objectId: id,
        objectName: updated.name,
        after: updated,
      },
    };
  },
);

export const DELETE = route({ area: "sdwan", section: "sdwan" }, async ({ auth, params }) => {
  const id = Number(params.id);
  await deletePolicy(auth.tenantId, id);
  return { data: { ok: true }, audit: { action: "policy.delete", objectType: "sdwan_policy", objectId: id } };
});
