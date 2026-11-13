/** DNS filtering policies (M06 §3) — RPZ-style list. */

import { route } from "@/lib/api/handler";
import { dnsPolicyCreateSchema } from "@/lib/validators/dns-dhcp";
import { createPolicy, listPolicies } from "@/lib/dns/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "dns_dhcp" }, async ({ auth }) => {
  return { data: await listPolicies(auth.tenantId) };
});

export const POST = route(
  { area: "dns_dhcp", bodySchema: dnsPolicyCreateSchema, section: "dns" },
  async ({ auth, body }) => {
    const created = await createPolicy(auth.tenantId, body);
    return {
      data: created,
      audit: { action: "dns_policy.create", objectType: "dns_policy", objectId: created.id, objectName: created.name, after: created },
    };
  },
);
