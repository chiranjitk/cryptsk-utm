/** Auto-block rule item (M13 §2.11) — update / delete, audit `threat_autoblock.update|delete`. */

import { route, numericId } from "@/lib/api/handler";
import { autoBlockUpdateSchema } from "@/lib/validators/threat-intel";
import { deleteAutoBlockRule, updateAutoBlockRule } from "@/lib/threat-intel/service";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "threat_intel", bodySchema: autoBlockUpdateSchema, section: "threat_intel" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const updated = await updateAutoBlockRule(auth.tenantId, id, body);
    return {
      data: updated,
      audit: {
        action: "threat_autoblock.update",
        objectType: "auto_block_rule",
        objectId: id,
        objectName: updated.name,
        after: updated,
      },
    };
  },
);

export const DELETE = route({ area: "threat_intel", section: "threat_intel" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  await deleteAutoBlockRule(auth.tenantId, id);
  return {
    data: { ok: true },
    audit: { action: "threat_autoblock.delete", objectType: "auto_block_rule", objectId: id },
  };
});
