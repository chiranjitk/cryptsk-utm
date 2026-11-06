/** DNS policy item (M06 §3) — update / delete. */

import { route } from "@/lib/api/handler";
import { dnsPolicyUpdateSchema } from "@/lib/validators/dns-dhcp";
import { deletePolicy, updatePolicy } from "@/lib/dns/service";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "dns_dhcp", bodySchema: dnsPolicyUpdateSchema, section: "dns" },
  async ({ auth, body, params }) => {
    const id = Number(params.id);
    const updated = await updatePolicy(auth.tenantId, id, body);
    return {
      data: updated,
      audit: { action: "dns_policy.update", objectType: "dns_policy", objectId: id, objectName: updated.name, after: updated },
    };
  },
);

export const DELETE = route({ area: "dns_dhcp", section: "dns" }, async ({ auth, params }) => {
  const id = Number(params.id);
  await deletePolicy(auth.tenantId, id);
  return { data: { ok: true }, audit: { action: "dns_policy.delete", objectType: "dns_policy", objectId: id } };
});
