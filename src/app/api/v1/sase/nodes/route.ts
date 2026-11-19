/**
 * /api/v1/sase/nodes — SASE cloud firewall node registry (spec §4.2).
 * GET lists the tenant's nodes, POST creates one (unique tenant+name —
 * duplicates surface as 409). RBAC area "sase" (read: admins + soc_analysts,
 * write: admins) — same matrix shape as the incident routes.
 */

import { route } from "@/lib/api/handler";
import { saseNodeCreateSchema } from "@/lib/validators/sase";
import { createNode, listNodes } from "@/lib/sase/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "sase" }, async ({ auth }) => {
  return { data: await listNodes(auth.tenantId) };
});

export const POST = route(
  { area: "sase", bodySchema: saseNodeCreateSchema, section: "sase" },
  async ({ auth, body }) => {
    const created = await createNode(auth.tenantId, body);
    return {
      data: created,
      audit: {
        action: "sase.node.create",
        objectType: "sase_node",
        objectId: created.id,
        objectName: created.name,
        after: created,
      },
    };
  },
);
