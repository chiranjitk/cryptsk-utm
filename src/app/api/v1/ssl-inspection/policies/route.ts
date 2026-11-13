/**
 * SSL inspection policies (M15 §2.1) — GET list + POST create.
 * signingCaId is validated server-side: mode selective/full require an
 * existing ACTIVE CA of type root|subordinate (VALIDATION_ERROR otherwise).
 * Mutations audit `ssl_policy.*` and snapshot section `ssl_inspection`.
 */

import { route } from "@/lib/api/handler";
import { sslPolicyCreateSchema } from "@/lib/validators/ssl-inspection";
import { createPolicy, listPolicies } from "@/app/api/v1/ssl-inspection/shared";

export const dynamic = "force-dynamic";

export const GET = route({ area: "ssl_inspection" }, async ({ auth }) => {
  return { data: await listPolicies(auth.tenantId) };
});

export const POST = route(
  { area: "ssl_inspection", bodySchema: sslPolicyCreateSchema, section: "ssl_inspection" },
  async ({ auth, body }) => {
    const created = await createPolicy(auth.tenantId, body);
    return {
      data: created,
      audit: { action: "ssl_policy.create", objectType: "ssl_policy", objectId: created.id, objectName: created.name, after: created },
    };
  },
);
