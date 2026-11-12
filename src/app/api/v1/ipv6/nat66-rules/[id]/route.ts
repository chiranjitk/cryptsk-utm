/** NAT66 rule item (M21 §2.7) — update / delete, audit `nat66.update|delete`. */

import { route, numericId } from "@/lib/api/handler";
import { nat66UpdateSchema } from "@/lib/validators/ipv6";
import { deleteNat66Rule, updateNat66Rule } from "@/app/api/v1/ipv6/shared";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "ipv6", bodySchema: nat66UpdateSchema, section: "ipv6" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const updated = await updateNat66Rule(auth.tenantId, id, body);
    return {
      data: updated,
      audit: {
        action: "nat66.update",
        objectType: "nat66_rule",
        objectId: id,
        objectName: updated.name,
        after: updated,
      },
    };
  },
);

export const DELETE = route({ area: "ipv6", section: "ipv6" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  await deleteNat66Rule(auth.tenantId, id);
  return { data: { ok: true }, audit: { action: "nat66.delete", objectType: "nat66_rule", objectId: id } };
});
