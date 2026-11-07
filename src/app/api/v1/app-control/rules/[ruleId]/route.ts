/**
 * App control rule item (M18 §2.2.2) — update / delete by ruleId, audit
 * `app_control.rule.update|delete`. Switching the inline action to `limit`
 * keeps the stored bandwidth when the caller doesn't send a new one.
 */

import { route } from "@/lib/api/handler";
import { ruleUpdateSchema } from "@/lib/validators/app-control";
import { deleteRule, updateRule } from "@/app/api/v1/app-control/service";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "app_control", bodySchema: ruleUpdateSchema, section: "app_control" },
  async ({ auth, body, params }) => {
    const ruleId = Number(params.ruleId);
    const updated = await updateRule(auth.tenantId, ruleId, body);
    return {
      data: updated,
      audit: {
        action: "app_control.rule.update",
        objectType: "app_control_rule",
        objectId: ruleId,
        objectName: updated.appName,
        after: updated,
      },
    };
  },
);

export const DELETE = route({ area: "app_control", section: "app_control" }, async ({ auth, params }) => {
  const ruleId = Number(params.ruleId);
  await deleteRule(auth.tenantId, ruleId);
  return {
    data: { ok: true },
    audit: { action: "app_control.rule.delete", objectType: "app_control_rule", objectId: ruleId },
  };
});
