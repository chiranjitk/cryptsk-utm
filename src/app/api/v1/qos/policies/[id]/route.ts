/**
 * QoS policy item (M08 §3) — update / delete. Delete cascades the policy's
 * QosRule rows but is 409 CONFLICT-ed while any FirewallRule.qosPolicyId
 * references it (body details list the referencing rule names).
 */

import { route } from "@/lib/api/handler";
import { qosPolicyUpdateSchema } from "@/lib/validators/qos";
import { deletePolicy, updatePolicy } from "@/lib/qos/service";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "qos", bodySchema: qosPolicyUpdateSchema, section: "qos" },
  async ({ auth, body, params }) => {
    const id = Number(params.id);
    const updated = await updatePolicy(auth.tenantId, id, body);
    return {
      data: updated,
      audit: { action: "qos_policy.update", objectType: "qos_policy", objectId: id, objectName: updated.name, after: updated },
    };
  },
);

export const DELETE = route({ area: "qos", section: "qos" }, async ({ auth, params }) => {
  const id = Number(params.id);
  const cascaded = await deletePolicy(auth.tenantId, id);
  return {
    data: { ok: true, cascaded },
    audit: { action: "qos_policy.delete", objectType: "qos_policy", objectId: id, after: cascaded },
  };
});
