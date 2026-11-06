/**
 * PUT/DELETE /api/v1/network/port-mirrors/{id} — replace / delete a SPAN
 * session. PUT re-checks src/dst existence and the one-active-per-srcIface
 * rule (also on re-enable); duplicate names fail with 409 via P2002.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { idParamSchema, mirrorBodySchema } from "@/lib/validators/network";
import { assertIfacesExist } from "@/lib/network/iface-service";
import { shapeMirror } from "@/lib/network/shapes";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "network", bodySchema: mirrorBodySchema, section: "interfaces" },
  async ({ auth, params, body }) => {
    const { id } = idParamSchema.parse(params);
    const before = await db.portMirror.findFirst({ where: { id, tenantId: auth.tenantId } });
    if (!before) throw ApiError.notFound(`Port mirror ${id} not found`);

    await assertIfacesExist(auth.tenantId, [body.srcIface, body.dstIface]);

    // re-enabling must also respect the one-active-per-src rule (M02 §3)
    if (body.enabled) {
      const clash = await db.portMirror.findFirst({
        where: { tenantId: auth.tenantId, srcIface: body.srcIface, enabled: true, id: { not: id } },
      });
      if (clash) throw ApiError.conflict(`A mirror for ${body.srcIface} already exists`);
    }

    const updated = await db.portMirror.update({
      where: { id },
      data: {
        name: body.name,
        srcIface: body.srcIface,
        dstIface: body.dstIface,
        direction: body.direction,
        enabled: body.enabled,
        description: body.description ?? null,
      },
    });
    return {
      data: shapeMirror(updated),
      audit: {
        action: "mirror.update",
        objectType: "port_mirror",
        objectId: id,
        objectName: before.name,
        before: shapeMirror(before),
        after: shapeMirror(updated),
      },
    };
  },
);

export const DELETE = route({ area: "network", section: "interfaces" }, async ({ auth, params }) => {
  const { id } = idParamSchema.parse(params);
  const row = await db.portMirror.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!row) throw ApiError.notFound(`Port mirror ${id} not found`);

  await db.portMirror.delete({ where: { id } });
  return {
    data: { ok: true },
    audit: {
      action: "mirror.delete",
      objectType: "port_mirror",
      objectId: row.id,
      objectName: row.name,
      before: shapeMirror(row),
    },
  };
});
