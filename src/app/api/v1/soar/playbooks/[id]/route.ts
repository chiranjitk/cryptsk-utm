/**
 * /api/v1/soar/playbooks/[id] — single playbook: GET, PATCH (partial update —
 * actions are re-validated against the action grammar), DELETE (cascades the
 * playbook's run rows — logical ref, no FK).
 */

import { route, numericId } from "@/lib/api/handler";
import { soarPlaybookUpdateSchema } from "@/lib/validators/soar";
import { deletePlaybook, getPlaybook, updatePlaybook } from "@/lib/soar/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "soar" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  return { data: await getPlaybook(auth.tenantId, id) };
});

export const PATCH = route(
  { area: "soar", bodySchema: soarPlaybookUpdateSchema },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const updated = await updatePlaybook(auth.tenantId, id, body);
    return {
      data: updated,
      audit: {
        action: "soar.playbook.update",
        objectType: "soar_playbook",
        objectId: id,
        objectName: updated.name,
        after: updated,
      },
    };
  },
);

export const DELETE = route({ area: "soar" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  const deleted = await deletePlaybook(auth.tenantId, id);
  return { data: deleted, audit: { action: "soar.playbook.delete", objectType: "soar_playbook", objectId: id } };
});
