/**
 * App control rules under one policy (M18 §2.2.2) — GET list + POST create.
 * appName must be a known nDPI catalog label; userGroupIds are validated
 * against the tenant's groups. Mutations audit `app_control.rule.create`.
 */

import { route } from "@/lib/api/handler";
import { ruleCreateSchema } from "@/lib/validators/app-control";
import { createRule, listRules } from "@/app/api/v1/app-control/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "app_control" }, async ({ auth, params }) => {
  const policyId = Number(params.id);
  return { data: await listRules(auth.tenantId, policyId) };
});

export const POST = route(
  { area: "app_control", bodySchema: ruleCreateSchema, section: "app_control" },
  async ({ auth, body, params }) => {
    const policyId = Number(params.id);
    const created = await createRule(auth.tenantId, policyId, body);
    return {
      data: created,
      audit: {
        action: "app_control.rule.create",
        objectType: "app_control_rule",
        objectId: created.id,
        objectName: created.appName,
        after: created,
      },
    };
  },
);
