/**
 * SSL inspection bypass rule item (M15 §2.1) — update / delete.
 * Partial updates re-validate the EFFECTIVE matchType/matchValue pair.
 * Mutations audit `ssl_bypass_rule.*` and snapshot section `ssl_inspection`.
 */

import { route } from "@/lib/api/handler";
import { sslBypassRuleUpdateSchema } from "@/lib/validators/ssl-inspection";
import { deleteBypassRule, updateBypassRule } from "@/app/api/v1/ssl-inspection/shared";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "ssl_inspection", bodySchema: sslBypassRuleUpdateSchema, section: "ssl_inspection" },
  async ({ auth, body, params }) => {
    const id = Number(params.id);
    const updated = await updateBypassRule(auth.tenantId, id, body);
    return {
      data: updated,
      audit: {
        action: "ssl_bypass_rule.update",
        objectType: "ssl_bypass_rule",
        objectId: id,
        objectName: updated.matchValue,
        after: updated,
      },
    };
  },
);

export const DELETE = route({ area: "ssl_inspection", section: "ssl_inspection" }, async ({ auth, params }) => {
  const id = Number(params.id);
  const removed = await deleteBypassRule(auth.tenantId, id);
  return {
    data: { ok: true },
    audit: { action: "ssl_bypass_rule.delete", objectType: "ssl_bypass_rule", objectId: id, objectName: removed.matchValue },
  };
});
