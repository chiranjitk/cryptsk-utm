/**
 * SD-WAN path-selection policies (M20 §2.5) — GET list + POST create.
 * Mutations audit `policy.create` and snapshot section `sdwan`.
 */

import { route } from "@/lib/api/handler";
import { policyCreateSchema } from "@/lib/validators/sdwan";
import { createPolicy, listPolicies } from "@/app/api/v1/sdwan/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "sdwan" }, async ({ auth }) => {
  return { data: await listPolicies(auth.tenantId) };
});

export const POST = route(
  { area: "sdwan", bodySchema: policyCreateSchema, section: "sdwan" },
  async ({ auth, body }) => {
    const created = await createPolicy(auth.tenantId, body);
    return {
      data: created,
      audit: {
        action: "policy.create",
        objectType: "sdwan_policy",
        objectId: created.id,
        objectName: created.name,
        after: created,
      },
    };
  },
);
