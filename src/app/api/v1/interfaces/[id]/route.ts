/**
 * GET/PUT/DELETE /api/v1/interfaces/{id} — detail, update, delete.
 * Delete cascades per M02 §2: WAN policy → zone interfaceNames refs →
 * StaticRoute soft refs (nulled) → the row itself, all in one transaction.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { idParamSchema, ifaceUpdateSchema } from "@/lib/validators/network";
import { deleteIface, loadShapedIfaces, updateIface } from "@/lib/network/iface-service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "network" }, async ({ auth, params }) => {
  const { id } = idParamSchema.parse(params);
  const shaped = (await loadShapedIfaces(auth.tenantId)).find((i) => i.id === id);
  if (!shaped) throw ApiError.notFound(`Interface ${id} not found`);
  return { data: shaped };
});

export const PUT = route(
  { area: "network", bodySchema: ifaceUpdateSchema, section: "interfaces" },
  async ({ auth, params, body }) => {
    const { id } = idParamSchema.parse(params);
    const raw = await db.networkInterface.findFirst({ where: { id, tenantId: auth.tenantId } });
    if (!raw) throw ApiError.notFound(`Interface ${id} not found`);
    const before = (await loadShapedIfaces(auth.tenantId)).find((i) => i.id === id) ?? null;

    const updated = await updateIface(auth.tenantId, id, body, raw);
    const after = (await loadShapedIfaces(auth.tenantId)).find((i) => i.id === id) ?? null;

    return {
      data: after,
      os: updated.os,
      audit: {
        action: "iface.update",
        objectType: "interface",
        objectId: id,
        objectName: raw.name,
        before,
        after,
      },
    };
  },
);

export const DELETE = route({ area: "network", section: "interfaces" }, async ({ auth, params }) => {
  const { id } = idParamSchema.parse(params);
  const raw = await db.networkInterface.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!raw) throw ApiError.notFound(`Interface ${id} not found`);

  const deleted = await deleteIface(auth.tenantId, raw);
  return {
    data: { ok: true },
    os: deleted.os,
    audit: {
      action: "iface.delete",
      objectType: "interface",
      objectId: deleted.id,
      objectName: deleted.name,
    },
  };
});
