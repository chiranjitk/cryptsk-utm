/**
 * BGP neighbor item (M19 §2.6) — update / delete, audit
 * `bgp_neighbor.update|delete`. Password stays write-only: absent field keeps
 * the stored value, explicit null clears it.
 */

import { route } from "@/lib/api/handler";
import { bgpNeighborUpdateSchema } from "@/lib/validators/dynamic-routing";
import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { assertNeighborRefs, toNeighborDTO } from "../../../internal";

export const dynamic = "force-dynamic";

async function findNeighbor(tenantId: number, id: number) {
  const row = await db.bgpNeighbor.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("BGP neighbor not found");
  return row;
}

export const PUT = route(
  { area: "dynamic_routing", bodySchema: bgpNeighborUpdateSchema, section: "dynamic_routing" },
  async ({ auth, body, params }) => {
    const id = Number(params.id);
    const existing = await findNeighbor(auth.tenantId, id);
    await assertNeighborRefs(auth.tenantId, body);

    const { password, ...rest } = body;
    const updated = await db.bgpNeighbor.update({
      where: { id },
      data: {
        ...rest,
        ...(password === undefined ? {} : { password: password ?? null }),
      },
    });
    return {
      data: toNeighborDTO(updated),
      audit: {
        action: "bgp_neighbor.update",
        objectType: "bgp_neighbor",
        objectId: id,
        objectName: updated.name,
        before: toNeighborDTO(existing),
        after: toNeighborDTO(updated),
      },
    };
  },
);

export const DELETE = route(
  { area: "dynamic_routing", section: "dynamic_routing" },
  async ({ auth, params }) => {
    const id = Number(params.id);
    const existing = await findNeighbor(auth.tenantId, id);
    await db.bgpNeighbor.delete({ where: { id } });
    return {
      data: { ok: true },
      audit: {
        action: "bgp_neighbor.delete",
        objectType: "bgp_neighbor",
        objectId: id,
        objectName: existing.name,
        before: toNeighborDTO(existing),
      },
    };
  },
);
