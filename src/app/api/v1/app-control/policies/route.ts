/**
 * Application Control policies (M18 §2.2.1) — GET list + POST create.
 * Mutations audit `app_control.policy.create` and snapshot section `app_control`.
 */

import { route } from "@/lib/api/handler";
import { policyCreateSchema } from "@/lib/validators/app-control";
import { createPolicy, listPolicies } from "@/app/api/v1/app-control/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "app_control" }, async ({ auth }) => {
  return { data: await listPolicies(auth.tenantId) };
});

export const POST = route(
  { area: "app_control", bodySchema: policyCreateSchema, section: "app_control" },
  async ({ auth, body }) => {
    const created = await createPolicy(auth.tenantId, body);
    return {
      data: created,
      audit: {
        action: "app_control.policy.create",
        objectType: "app_control_policy",
        objectId: created.id,
        objectName: created.name,
        after: created,
      },
    };
  },
);
