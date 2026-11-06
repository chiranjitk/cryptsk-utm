/**
 * GET  /api/v1/routes — static routes sorted by destinationCidr then distance
 * (M02 §4 tab 1; ordering is not user-managed). Filters: ?iface= ?q= ?enabled=.
 * POST /api/v1/routes — create; unknown interfaceName → 400 (logical-ref check).
 */

import { route } from "@/lib/api/handler";
import { db } from "@/lib/db";
import { netListQuery, routeBodySchema } from "@/lib/validators/network";
import { assertIfacesExist } from "@/lib/network/iface-service";
import { shapeStaticRoute } from "@/lib/network/shapes";

export const dynamic = "force-dynamic";

export const GET = route({ area: "network", querySchema: netListQuery }, async ({ auth, query }) => {
  let rows = await db.staticRoute.findMany({
    where: { tenantId: auth.tenantId },
    orderBy: [{ destinationCidr: "asc" }, { distance: "asc" }],
  });
  const shaped = rows.map(shapeStaticRoute);

  if (query.iface) return { data: shaped.filter((r) => r.interfaceName === query.iface) };
  if (query.enabled) return { data: shaped.filter((r) => r.enabled === (query.enabled === "true")) };
  const q = (query.q ?? "").trim().toLowerCase();
  if (q) {
    return {
      data: shaped.filter(
        (r) =>
          r.destinationCidr.toLowerCase().includes(q) ||
          (r.name ?? "").toLowerCase().includes(q) ||
          (r.gateway ?? "").toLowerCase().includes(q),
      ),
    };
  }
  return { data: shaped };
});

export const POST = route(
  { area: "network", bodySchema: routeBodySchema, section: "routing" },
  async ({ auth, body }) => {
    if (body.interfaceName) await assertIfacesExist(auth.tenantId, [body.interfaceName]);

    const created = await db.staticRoute.create({
      data: {
        tenantId: auth.tenantId,
        name: body.name ?? null,
        destinationCidr: body.destinationCidr,
        gateway: body.gateway ?? null,
        interfaceName: body.interfaceName ?? null,
        distance: body.distance,
        bfd: body.bfd,
        blackhole: body.blackhole,
        enabled: body.enabled,
        description: body.description ?? null,
      },
    });
    return {
      data: shapeStaticRoute(created),
      audit: {
        action: "route.create",
        objectType: "static_route",
        objectId: created.id,
        objectName: created.name ?? created.destinationCidr,
      },
    };
  },
);
