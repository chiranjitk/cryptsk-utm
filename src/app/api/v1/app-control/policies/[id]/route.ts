/**
 * App control policy item (M18 §2.2.1) — update / delete, audit
 * `app_control.policy.update|delete`. Deleting is rejected 409 CONFLICT with a
 * `referencedBy` detail while application rules exist under the policy.
 */

import { route } from "@/lib/api/handler";
import { policyUpdateSchema } from "@/lib/validators/app-control";
import { deletePolicy, updatePolicy } from "@/app/api/v1/app-control/service";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "app_control", bodySchema: policyUpdateSchema, section: "app_control" },
  async ({ auth, body, params }) => {
    const id = Number(params.id);
    const updated = await updatePolicy(auth.tenantId, id, body);
    return {
      data: updated,
      audit: {
        action: "app_control.policy.update",
        objectType: "app_control_policy",
        objectId: id,
        objectName: updated.name,
        after: updated,
      },
    };
  },
);

export const DELETE = route({ area: "app_control", section: "app_control" }, async ({ auth, params }) => {
  const id = Number(params.id);
  await deletePolicy(auth.tenantId, id);
  return {
    data: { ok: true },
    audit: { action: "app_control.policy.delete", objectType: "app_control_policy", objectId: id },
  };
});
