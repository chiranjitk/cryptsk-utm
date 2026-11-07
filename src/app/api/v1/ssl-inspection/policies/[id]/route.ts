/**
 * SSL inspection policy item (M15 §2.1) — update / delete.
 * Delete removes the policy together with its bypass rules (logical refs).
 * Mutations audit `ssl_policy.*` and snapshot section `ssl_inspection`.
 */

import { route } from "@/lib/api/handler";
import { sslPolicyUpdateSchema } from "@/lib/validators/ssl-inspection";
import { deletePolicy, updatePolicy } from "@/app/api/v1/ssl-inspection/shared";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "ssl_inspection", bodySchema: sslPolicyUpdateSchema, section: "ssl_inspection" },
  async ({ auth, body, params }) => {
    const id = Number(params.id);
    const updated = await updatePolicy(auth.tenantId, id, body);
    return {
      data: updated,
      audit: { action: "ssl_policy.update", objectType: "ssl_policy", objectId: id, objectName: updated.name, after: updated },
    };
  },
);

export const DELETE = route({ area: "ssl_inspection", section: "ssl_inspection" }, async ({ auth, params }) => {
  const id = Number(params.id);
  const removed = await deletePolicy(auth.tenantId, id);
  return { data: { ok: true }, audit: { action: "ssl_policy.delete", objectType: "ssl_policy", objectId: id, objectName: removed.name } };
});
