/** QoS rule item (M08 §3) — update (priority slider re-orders) / delete. */

import { route } from "@/lib/api/handler";
import { qosRuleUpdateSchema } from "@/lib/validators/qos";
import { deleteRule, updateRule } from "@/lib/qos/service";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "qos", bodySchema: qosRuleUpdateSchema, section: "qos" },
  async ({ auth, body, params }) => {
    const id = Number(params.id);
    const updated = await updateRule(auth.tenantId, id, body);
    return {
      data: updated,
      audit: { action: "qos_rule.update", objectType: "qos_rule", objectId: id, objectName: updated.name, after: updated },
    };
  },
);

export const DELETE = route({ area: "qos", section: "qos" }, async ({ auth, params }) => {
  const id = Number(params.id);
  await deleteRule(auth.tenantId, id);
  return {
    data: { ok: true },
    audit: { action: "qos_rule.delete", objectType: "qos_rule", objectId: id },
  };
});
