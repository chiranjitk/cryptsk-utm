/**
 * /api/v1/ztna/policies/[id] — update (subject/action/posture gate/schedule/
 * enabled toggle) and delete a single access policy.
 */

import { route, numericId } from "@/lib/api/handler";
import { ztnaPolicyUpdateSchema } from "@/lib/validators/ztna";
import { deletePolicy, updatePolicy } from "@/lib/ztna/service";

export const dynamic = "force-dynamic";

export const PATCH = route(
  { area: "ztna", bodySchema: ztnaPolicyUpdateSchema, section: "ztna" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const updated = await updatePolicy(auth.tenantId, id, body);
    return {
      data: updated,
      audit: {
        action: "ztna.policy.update",
        objectType: "ztna_access_policy",
        objectId: id,
        objectName: `${updated.subjectType}:${updated.subjectRef} → ${updated.appName}`,
        after: updated,
      },
    };
  },
);

export const DELETE = route({ area: "ztna", section: "ztna" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  const deleted = await deletePolicy(auth.tenantId, id);
  return { data: deleted, audit: { action: "ztna.policy.delete", objectType: "ztna_access_policy", objectId: id } };
});
