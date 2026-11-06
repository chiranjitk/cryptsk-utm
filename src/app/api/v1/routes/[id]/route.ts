/**
 * GET/PUT/DELETE /api/v1/routes/{id} — static route detail, replace, delete
 * (404s on missing; PUT re-validates the interfaceName logical ref).
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { idParamSchema, routeBodySchema } from "@/lib/validators/network";
import { assertIfacesExist } from "@/lib/network/iface-service";
import { shapeStaticRoute } from "@/lib/network/shapes";

export const dynamic = "force-dynamic";

export const GET = route({ area: "network" }, async ({ auth, params }) => {
  const { id } = idParamSchema.parse(params);
  const row = await db.staticRoute.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!row) throw ApiError.notFound(`Route ${id} not found`);
  return { data: shapeStaticRoute(row) };
});

export const PUT = route(
  { area: "network", bodySchema: routeBodySchema, section: "routing" },
  async ({ auth, params, body }) => {
    const { id } = idParamSchema.parse(params);
    const before = await db.staticRoute.findFirst({ where: { id, tenantId: auth.tenantId } });
    if (!before) throw ApiError.notFound(`Route ${id} not found`);
    if (body.interfaceName) await assertIfacesExist(auth.tenantId, [body.interfaceName]);

    const updated = await db.staticRoute.update({
      where: { id },
      data: {
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
      data: shapeStaticRoute(updated),
      audit: {
        action: "route.update",
        objectType: "static_route",
        objectId: id,
        objectName: before.name ?? before.destinationCidr,
        before: shapeStaticRoute(before),
        after: shapeStaticRoute(updated),
      },
    };
  },
);

export const DELETE = route({ area: "network", section: "routing" }, async ({ auth, params }) => {
  const { id } = idParamSchema.parse(params);
  const row = await db.staticRoute.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!row) throw ApiError.notFound(`Route ${id} not found`);

  await db.staticRoute.delete({ where: { id } });
  return {
    data: { ok: true },
    audit: {
      action: "route.delete",
      objectType: "static_route",
      objectId: row.id,
      objectName: row.name ?? row.destinationCidr,
      before: shapeStaticRoute(row),
    },
  };
});
