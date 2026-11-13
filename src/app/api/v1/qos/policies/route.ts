/** QoS policies (M08 §3) — list (incl. ruleCount + attached iface state) / create. */

import { route } from "@/lib/api/handler";
import { qosPolicyCreateSchema } from "@/lib/validators/qos";
import { createPolicy, listPolicies } from "@/lib/qos/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "qos" }, async ({ auth }) => {
  return { data: await listPolicies(auth.tenantId) };
});

export const POST = route(
  { area: "qos", bodySchema: qosPolicyCreateSchema, section: "qos" },
  async ({ auth, body }) => {
    const created = await createPolicy(auth.tenantId, body);
    return {
      data: created,
      audit: { action: "qos_policy.create", objectType: "qos_policy", objectId: created.id, objectName: created.name, after: created },
    };
  },
);
