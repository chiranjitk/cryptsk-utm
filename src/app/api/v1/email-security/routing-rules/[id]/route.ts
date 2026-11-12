/**
 * Email routing rule item (M22 §2.8.3) — update / delete. Priority
 * uniqueness per tenant is re-checked on PUT (409 CONFLICT). Mutations audit
 * `email_routing_rule.update|delete`, snapshot section `email_security`.
 */

import { route, numericId } from "@/lib/api/handler";
import { routingRuleUpdateSchema } from "@/lib/validators/email-security";
import { deleteRoutingRule, updateRoutingRule } from "@/app/api/v1/email-security/service";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "email_security", bodySchema: routingRuleUpdateSchema, section: "email_security" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const updated = await updateRoutingRule(auth.tenantId, id, body);
    return {
      data: updated,
      audit: {
        action: "email_routing_rule.update",
        objectType: "email_routing_rule",
        objectId: id,
        objectName: updated.name,
        after: updated,
      },
    };
  },
);

export const DELETE = route(
  { area: "email_security", section: "email_security" },
  async ({ auth, params }) => {
    const id = numericId(params, "id");
    await deleteRoutingRule(auth.tenantId, id);
    return {
      data: { ok: true },
      audit: { action: "email_routing_rule.delete", objectType: "email_routing_rule", objectId: id },
    };
  },
);
