/**
 * /api/v1/sase/nodes/[id] — single SASE node: GET, PATCH (partial update —
 * endpoint/subnets/status transitions feed the mesh plan), DELETE (rejected
 * with 409 while any tunnel still references the node).
 */

import { route, numericId } from "@/lib/api/handler";
import { saseNodeUpdateSchema } from "@/lib/validators/sase";
import { deleteNode, getNode, updateNode } from "@/lib/sase/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "sase" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  return { data: await getNode(auth.tenantId, id) };
});

export const PATCH = route(
  { area: "sase", bodySchema: saseNodeUpdateSchema, section: "sase" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const updated = await updateNode(auth.tenantId, id, body);
    return {
      data: updated,
      audit: {
        action: "sase.node.update",
        objectType: "sase_node",
        objectId: id,
        objectName: updated.name,
        after: updated,
      },
    };
  },
);

export const DELETE = route({ area: "sase", section: "sase" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  const deleted = await deleteNode(auth.tenantId, id);
  return { data: deleted, audit: { action: "sase.node.delete", objectType: "sase_node", objectId: id } };
});
