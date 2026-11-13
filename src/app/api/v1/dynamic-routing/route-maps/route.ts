/**
 * Route maps (M19 §2.6 policy objects) — GET list + POST create. Entries are
 * stored as JSON ({seq, action, matchPrefixListId?, setLocalPref?, …}).
 */

import { route } from "@/lib/api/handler";
import { routeMapCreateSchema } from "@/lib/validators/dynamic-routing";
import { db } from "@/lib/db";
import { toRouteMapDTO } from "@/app/api/v1/dynamic-routing/internal";

export const dynamic = "force-dynamic";

export const GET = route({ area: "dynamic_routing" }, async ({ auth }) => {
  const rows = await db.routeMap.findMany({
    where: { tenantId: auth.tenantId },
    orderBy: [{ name: "asc" }],
  });
  return { data: rows.map(toRouteMapDTO) };
});

export const POST = route(
  { area: "dynamic_routing", bodySchema: routeMapCreateSchema, section: "dynamic_routing" },
  async ({ auth, body }) => {
    const created = await db.routeMap.create({
      data: {
        tenantId: auth.tenantId,
        name: body.name,
        entries: JSON.stringify(body.entries),
      },
    });
    return {
      data: toRouteMapDTO(created),
      audit: {
        action: "route_map.create",
        objectType: "route_map",
        objectId: created.id,
        objectName: created.name,
        after: toRouteMapDTO(created),
      },
    };
  },
);
