/**
 * Email routing rules (M22 §2.8.3) — GET list + POST create. Duplicate
 * priority per tenant → 409 CONFLICT from the service. Mutations audit
 * `email_routing_rule.create` and snapshot section `email_security`.
 */

import { route } from "@/lib/api/handler";
import { routingRuleCreateSchema } from "@/lib/validators/email-security";
import { createRoutingRule, listRoutingRules } from "@/app/api/v1/email-security/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "email_security" }, async ({ auth }) => {
  return { data: await listRoutingRules(auth.tenantId) };
});

export const POST = route(
  { area: "email_security", bodySchema: routingRuleCreateSchema, section: "email_security" },
  async ({ auth, body }) => {
    const created = await createRoutingRule(auth.tenantId, body);
    return {
      data: created,
      audit: {
        action: "email_routing_rule.create",
        objectType: "email_routing_rule",
        objectId: created.id,
        objectName: created.name,
        after: created,
      },
    };
  },
);
