/**
 * URL filter policy item (M16 §2.3.1) — update / delete, audit
 * `url_filter.policy.update|delete`. Deleting a policy cascades its category
 * rules + custom lists (logs keep the dangling logical policyId by design).
 */

import { route, numericId } from "@/lib/api/handler";
import { policyUpdateSchema } from "@/lib/validators/url-filter";
import { deletePolicy, updatePolicy } from "@/app/api/v1/url-filter/service";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "url_filter", bodySchema: policyUpdateSchema, section: "url_filter" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const updated = await updatePolicy(auth.tenantId, id, body);
    return {
      data: updated,
      audit: {
        action: "url_filter.policy.update",
        objectType: "url_filter_policy",
        objectId: id,
        objectName: updated.name,
        after: updated,
      },
    };
  },
);

export const DELETE = route({ area: "url_filter", section: "url_filter" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  await deletePolicy(auth.tenantId, id);
  return {
    data: { ok: true },
    audit: { action: "url_filter.policy.delete", objectType: "url_filter_policy", objectId: id },
  };
});
