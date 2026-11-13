/**
 * SSL inspection bypass rules (M15 §2.1) — GET list (?policyId filter) +
 * POST create. Rules are evaluated in insertion order per policy; matchValue
 * is validated per matchType (domain/wildcard/category/ip/cidr). Mutations
 * audit `ssl_bypass_rule.*` and snapshot section `ssl_inspection`.
 */

import { route } from "@/lib/api/handler";
import { sslBypassRuleCreateSchema, sslBypassRuleQuerySchema } from "@/lib/validators/ssl-inspection";
import { createBypassRule, listBypassRules } from "@/app/api/v1/ssl-inspection/shared";

export const dynamic = "force-dynamic";

export const GET = route(
  { area: "ssl_inspection", querySchema: sslBypassRuleQuerySchema },
  async ({ auth, query }) => {
    return { data: await listBypassRules(auth.tenantId, query) };
  },
);

export const POST = route(
  { area: "ssl_inspection", bodySchema: sslBypassRuleCreateSchema, section: "ssl_inspection" },
  async ({ auth, body }) => {
    const created = await createBypassRule(auth.tenantId, body);
    return {
      data: created,
      audit: {
        action: "ssl_bypass_rule.create",
        objectType: "ssl_bypass_rule",
        objectId: created.id,
        objectName: created.matchValue,
        after: created,
      },
    };
  },
);
