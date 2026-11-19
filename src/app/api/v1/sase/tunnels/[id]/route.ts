/**
 * /api/v1/sase/tunnels/[id] — single mesh tunnel: PATCH (partial update —
 * endpoint swap re-runs the existence/self/duplicate-direction guards) and
 * DELETE. `pskRef` stays a secret-store REFERENCE string end to end.
 */

import { route, numericId } from "@/lib/api/handler";
import { saseTunnelUpdateSchema } from "@/lib/validators/sase";
import { deleteTunnel, updateTunnel } from "@/lib/sase/service";

export const dynamic = "force-dynamic";

export const PATCH = route(
  { area: "sase", bodySchema: saseTunnelUpdateSchema, section: "sase" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const updated = await updateTunnel(auth.tenantId, id, body);
    return {
      data: updated,
      audit: {
        action: "sase.tunnel.update",
        objectType: "sase_tunnel",
        objectId: id,
        objectName: updated.name,
        after: updated,
      },
    };
  },
);

export const DELETE = route({ area: "sase", section: "sase" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  const deleted = await deleteTunnel(auth.tenantId, id);
  return { data: deleted, audit: { action: "sase.tunnel.delete", objectType: "sase_tunnel", objectId: id } };
});
