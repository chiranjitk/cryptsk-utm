/**
 * /api/v1/sase/tunnels — edge-to-cloud WireGuard mesh tunnel registry
 * (spec §4.2). POST validates both node ids exist (logical refs), rejects
 * self-tunnels and duplicate from → to pairs in the same direction.
 */

import { route } from "@/lib/api/handler";
import { saseTunnelCreateSchema } from "@/lib/validators/sase";
import { createTunnel, listTunnels } from "@/lib/sase/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "sase" }, async ({ auth }) => {
  return { data: await listTunnels(auth.tenantId) };
});

export const POST = route(
  { area: "sase", bodySchema: saseTunnelCreateSchema, section: "sase" },
  async ({ auth, body }) => {
    const created = await createTunnel(auth.tenantId, body);
    return {
      data: created,
      audit: {
        action: "sase.tunnel.create",
        objectType: "sase_tunnel",
        objectId: created.id,
        objectName: created.name,
        after: created,
      },
    };
  },
);
