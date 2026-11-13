/**
 * BGP neighbors (M19 §2.6) — GET list + POST create. Passwords are write-only:
 * stored as-is, never returned (GET responses carry hasPassword). Mutations
 * snapshot section `dynamic_routing`, audit `bgp_neighbor.create`.
 */

import { route } from "@/lib/api/handler";
import { bgpNeighborCreateSchema } from "@/lib/validators/dynamic-routing";
import { db } from "@/lib/db";
import { assertNeighborRefs, toNeighborDTO } from "../../internal";

export const dynamic = "force-dynamic";

export const GET = route({ area: "dynamic_routing" }, async ({ auth }) => {
  const rows = await db.bgpNeighbor.findMany({
    where: { tenantId: auth.tenantId },
    orderBy: [{ name: "asc" }],
  });
  return { data: rows.map(toNeighborDTO) };
});

export const POST = route(
  { area: "dynamic_routing", bodySchema: bgpNeighborCreateSchema, section: "dynamic_routing" },
  async ({ auth, body }) => {
    await assertNeighborRefs(auth.tenantId, body);
    const { password, ...rest } = body;
    const created = await db.bgpNeighbor.create({
      data: {
        tenantId: auth.tenantId,
        ...rest,
        password: password ?? null,
      },
    });
    return {
      data: toNeighborDTO(created),
      audit: {
        action: "bgp_neighbor.create",
        objectType: "bgp_neighbor",
        objectId: created.id,
        objectName: created.name,
        after: toNeighborDTO(created),
      },
    };
  },
);
