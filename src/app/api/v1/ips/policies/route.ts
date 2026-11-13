/**
 * /api/v1/ips/policies — list + create (M04 §3). area: ips_policies.
 * Section `ips` snapshots + `config:updated` broadcast on mutations.
 */

import { route } from "@/lib/api/handler";
import { db } from "@/lib/db";
import { ipsPolicyCreateSchema } from "@/lib/validators/ips";
import { createPolicy, listPolicies } from "@/lib/ips/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "ips_policies" }, async ({ auth }) => {
  return { data: await listPolicies(auth.tenantId) };
});

export const POST = route(
  { area: "ips_policies", bodySchema: ipsPolicyCreateSchema, section: "ips" },
  async ({ auth, body }) => {
    const created = await createPolicy(auth.tenantId, body);
    return {
      data: created,
      audit: { action: "ips_policy.create", objectType: "ips_policy", objectId: created.id, objectName: created.name },
    };
  },
);
