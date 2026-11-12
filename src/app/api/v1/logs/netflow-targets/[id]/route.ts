/** NetFlow target item (M09 §3) — update / delete, audit `netflow_target.update|delete`. */

import { route, numericId } from "@/lib/api/handler";
import { netflowTargetUpdateSchema } from "@/lib/validators/logs";
import { deleteNetflowTarget, updateNetflowTarget } from "@/lib/logs/service";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "log_forwarding", bodySchema: netflowTargetUpdateSchema, section: "system" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const updated = await updateNetflowTarget(auth.tenantId, id, body);
    return {
      data: updated,
      audit: { action: "netflow_target.update", objectType: "netflow_target", objectId: id, objectName: updated.name, after: updated },
    };
  },
);

export const DELETE = route({ area: "log_forwarding", section: "system" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  await deleteNetflowTarget(auth.tenantId, id);
  return { data: { ok: true }, audit: { action: "netflow_target.delete", objectType: "netflow_target", objectId: id } };
});
