/**
 * Route map item (M19 §2.6) — update / delete, audit `route_map.update|delete`.
 * Delete is guarded: 409 while a BGP neighbor references the map.
 */

import { route } from "@/lib/api/handler";
import { routeMapUpdateSchema } from "@/lib/validators/dynamic-routing";
import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { assertNotReferencedByNeighbor, toRouteMapDTO } from "../../internal";

export const dynamic = "force-dynamic";

async function findMap(tenantId: number, id: number) {
  const row = await db.routeMap.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("Route map not found");
  return row;
}

export const PUT = route(
  { area: "dynamic_routing", bodySchema: routeMapUpdateSchema, section: "dynamic_routing" },
  async ({ auth, body, params }) => {
    const id = Number(params.id);
    const existing = await findMap(auth.tenantId, id);
    const updated = await db.routeMap.update({
      where: { id },
      data: {
        ...(body.name === undefined ? {} : { name: body.name }),
        ...(body.entries === undefined ? {} : { entries: JSON.stringify(body.entries) }),
      },
    });
    return {
      data: toRouteMapDTO(updated),
      audit: {
        action: "route_map.update",
        objectType: "route_map",
        objectId: id,
        objectName: updated.name,
        before: toRouteMapDTO(existing),
        after: toRouteMapDTO(updated),
      },
    };
  },
);

export const DELETE = route(
  { area: "dynamic_routing", section: "dynamic_routing" },
  async ({ auth, params }) => {
    const id = Number(params.id);
    const existing = await findMap(auth.tenantId, id);
    await assertNotReferencedByNeighbor(auth.tenantId, "routeMapInId", id, existing.name);
    await assertNotReferencedByNeighbor(auth.tenantId, "routeMapOutId", id, existing.name);
    await db.routeMap.delete({ where: { id } });
    return {
      data: { ok: true },
      audit: {
        action: "route_map.delete",
        objectType: "route_map",
        objectId: id,
        objectName: existing.name,
        before: toRouteMapDTO(existing),
      },
    };
  },
);
