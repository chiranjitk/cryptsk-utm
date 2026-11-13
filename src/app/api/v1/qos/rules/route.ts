/**
 * QoS rules (M08 §3) — list (?policyId=, ordered priority asc / id asc) and
 * create (validation per M08 §5.2 in the service).
 */

import { route } from "@/lib/api/handler";
import { qosRuleCreateSchema, qosRulesQuerySchema } from "@/lib/validators/qos";
import { createRule, listRules } from "@/lib/qos/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "qos", querySchema: qosRulesQuerySchema }, async ({ auth, query }) => {
  return { data: await listRules(auth.tenantId, query.policyId) };
});

export const POST = route(
  { area: "qos", bodySchema: qosRuleCreateSchema, section: "qos" },
  async ({ auth, body }) => {
    const created = await createRule(auth.tenantId, body);
    return {
      data: created,
      audit: { action: "qos_rule.create", objectType: "qos_rule", objectId: created.id, objectName: created.name, after: created },
    };
  },
);
