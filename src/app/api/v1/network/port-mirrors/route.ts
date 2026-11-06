/**
 * GET  /api/v1/network/port-mirrors — SPAN sessions (M02 §4 tab 4)
 * POST /api/v1/network/port-mirrors — create; src/dst must exist and only one
 * ACTIVE mirror per srcIface is allowed (409, M02 §3 error table).
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { mirrorBodySchema, netListQuery } from "@/lib/validators/network";
import { assertIfacesExist } from "@/lib/network/iface-service";
import { shapeMirror } from "@/lib/network/shapes";

export const dynamic = "force-dynamic";

export const GET = route({ area: "network", querySchema: netListQuery }, async ({ auth }) => {
  const rows = await db.portMirror.findMany({ where: { tenantId: auth.tenantId }, orderBy: { id: "asc" } });
  return { data: rows.map(shapeMirror) };
});

export const POST = route(
  { area: "network", bodySchema: mirrorBodySchema, section: "interfaces" },
  async ({ auth, body }) => {
    await assertIfacesExist(auth.tenantId, [body.srcIface, body.dstIface]);

    // one active mirror per source iface (M02 §3)
    if (body.enabled) {
      const active = await db.portMirror.findFirst({
        where: { tenantId: auth.tenantId, srcIface: body.srcIface, enabled: true },
      });
      if (active) throw ApiError.conflict(`A mirror for ${body.srcIface} already exists`);
    }

    const created = await db.portMirror.create({
      data: {
        tenantId: auth.tenantId,
        name: body.name,
        srcIface: body.srcIface,
        dstIface: body.dstIface,
        direction: body.direction,
        enabled: body.enabled,
        description: body.description ?? null,
      },
    });
    return {
      data: shapeMirror(created),
      audit: { action: "mirror.create", objectType: "port_mirror", objectId: created.id, objectName: created.name },
    };
  },
);
