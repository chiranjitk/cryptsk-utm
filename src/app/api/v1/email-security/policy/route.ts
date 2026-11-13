/**
 * Email policy SINGLETON (M22 §2.8.2) — GET auto-creates the per-tenant
 * defaults row; PUT replaces the full form (audit `email_policy.update`,
 * snapshot section `email_security`).
 */

import { route } from "@/lib/api/handler";
import { policyUpdateSchema } from "@/lib/validators/email-security";
import { getOrCreatePolicy, updatePolicy } from "@/app/api/v1/email-security/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "email_security" }, async ({ auth }) => {
  return { data: await getOrCreatePolicy(auth.tenantId) };
});

export const PUT = route(
  { area: "email_security", bodySchema: policyUpdateSchema, section: "email_security" },
  async ({ auth, body }) => {
    const updated = await updatePolicy(auth.tenantId, body);
    return {
      data: updated,
      audit: {
        action: "email_policy.update",
        objectType: "email_policy",
        objectId: updated.id,
        objectName: updated.name,
        after: updated,
      },
    };
  },
);
