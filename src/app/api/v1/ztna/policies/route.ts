/**
 * /api/v1/ztna/policies — identity-based access rules (user/group/device →
 * app, allow|deny, optional posture gate + schedule). GET filters by appId.
 */

import { route } from "@/lib/api/handler";
import { ztnaPolicyCreateSchema, ztnaPolicyQuerySchema } from "@/lib/validators/ztna";
import { createPolicy, listPolicies } from "@/lib/ztna/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "ztna", querySchema: ztnaPolicyQuerySchema }, async ({ auth, query }) => {
  return { data: await listPolicies(auth.tenantId, query) };
});

export const POST = route(
  { area: "ztna", bodySchema: ztnaPolicyCreateSchema, section: "ztna" },
  async ({ auth, body }) => {
    const created = await createPolicy(auth.tenantId, body);
    return {
      data: created,
      audit: {
        action: "ztna.policy.create",
        objectType: "ztna_access_policy",
        objectId: created.id,
        objectName: `${created.subjectType}:${created.subjectRef} → ${created.appName}`,
        after: created,
      },
    };
  },
);
