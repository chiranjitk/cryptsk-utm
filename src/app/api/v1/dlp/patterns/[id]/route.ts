/** DLP pattern item (Phase 3 §3.3) — update + delete, audit `dlp.pattern.*`. */

import { route, numericId } from "@/lib/api/handler";
import { dlpPatternUpdateSchema } from "@/lib/validators/dlp";
import { deletePattern, updatePattern } from "@/lib/dlp/service";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "dlp", bodySchema: dlpPatternUpdateSchema, section: "dlp" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const updated = await updatePattern(auth.tenantId, id, body);
    return {
      data: updated,
      audit: {
        action: "dlp.pattern.update",
        objectType: "dlp_pattern",
        objectId: id,
        objectName: updated.name,
        after: updated,
      },
    };
  },
);

export const DELETE = route({ area: "dlp", section: "dlp" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  const { scrubbedPolicies } = await deletePattern(auth.tenantId, id);
  return {
    data: { ok: true, scrubbedPolicies },
    audit: { action: "dlp.pattern.delete", objectType: "dlp_pattern", objectId: id },
  };
});
