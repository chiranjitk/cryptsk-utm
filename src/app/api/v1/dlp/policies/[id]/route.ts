/** DLP policy item (Phase 3 §3.3) — update + delete, audit `dlp.policy.*`. */

import { route, numericId } from "@/lib/api/handler";
import { dlpPolicyUpdateSchema } from "@/lib/validators/dlp";
import { deletePolicy, updatePolicy } from "@/lib/dlp/service";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "dlp", bodySchema: dlpPolicyUpdateSchema, section: "dlp" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const updated = await updatePolicy(auth.tenantId, id, body);
    return {
      data: updated,
      audit: {
        action: "dlp.policy.update",
        objectType: "dlp_policy",
        objectId: id,
        objectName: updated.name,
        after: updated,
      },
    };
  },
);

export const DELETE = route({ area: "dlp", section: "dlp" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  await deletePolicy(auth.tenantId, id);
  return { data: { ok: true }, audit: { action: "dlp.policy.delete", objectType: "dlp_policy", objectId: id } };
});
