/**
 * DLP policies (Phase 3 §3.3) — GET list + POST create. Mutations audit
 * `dlp.policy.create` and snapshot section `dlp`. patternIds are validated
 * in-tenant by the service (unknown ids → 400).
 */

import { route } from "@/lib/api/handler";
import { dlpPolicyCreateSchema } from "@/lib/validators/dlp";
import { createPolicy, listPolicies } from "@/lib/dlp/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "dlp" }, async ({ auth }) => {
  return { data: await listPolicies(auth.tenantId) };
});

export const POST = route(
  { area: "dlp", bodySchema: dlpPolicyCreateSchema, section: "dlp" },
  async ({ auth, body }) => {
    const created = await createPolicy(auth.tenantId, body);
    return {
      data: created,
      audit: {
        action: "dlp.policy.create",
        objectType: "dlp_policy",
        objectId: created.id,
        objectName: created.name,
        after: created,
      },
    };
  },
);
