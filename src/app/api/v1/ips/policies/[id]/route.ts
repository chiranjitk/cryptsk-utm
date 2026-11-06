/**
 * /api/v1/ips/policies/[id] — update (editor save / enable toggle) and
 * delete (409 CONFLICT with referencing rule names while RESTRICT applies).
 */

import { route } from "@/lib/api/handler";
import { ipsPolicyUpdateSchema } from "@/lib/validators/ips";
import { deletePolicy, updatePolicy } from "@/lib/ips/service";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "ips_policies", bodySchema: ipsPolicyUpdateSchema, section: "ips" },
  async ({ auth, body, params }) => {
    const id = Number(params.id);
    const updated = await updatePolicy(auth.tenantId, id, body);
    return {
      data: updated,
      audit: { action: "ips_policy.update", objectType: "ips_policy", objectId: id, objectName: updated.name },
    };
  },
);

export const DELETE = route({ area: "ips_policies", section: "ips" }, async ({ auth, params }) => {
  const id = Number(params.id);
  await deletePolicy(auth.tenantId, id);
  return {
    data: { ok: true },
    audit: { action: "ips_policy.delete", objectType: "ips_policy", objectId: id },
  };
});
