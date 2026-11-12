/**
 * OSPF interface item (M19 §2.6) — update / delete, audit
 * `ospf_interface.update|delete`.
 */

import { route, numericId } from "@/lib/api/handler";
import { ospfInterfaceUpdateSchema } from "@/lib/validators/dynamic-routing";
import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";

export const dynamic = "force-dynamic";

async function findIface(tenantId: number, id: number) {
  const row = await db.ospfInterface.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("OSPF interface not found");
  return row;
}

export const PUT = route(
  { area: "dynamic_routing", bodySchema: ospfInterfaceUpdateSchema, section: "dynamic_routing" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const existing = await findIface(auth.tenantId, id);
    const updated = await db.ospfInterface.update({ where: { id }, data: body });
    return {
      data: updated,
      audit: {
        action: "ospf_interface.update",
        objectType: "ospf_interface",
        objectId: id,
        objectName: updated.interfaceName,
        before: existing,
        after: updated,
      },
    };
  },
);

export const DELETE = route(
  { area: "dynamic_routing", section: "dynamic_routing" },
  async ({ auth, params }) => {
    const id = numericId(params, "id");
    const existing = await findIface(auth.tenantId, id);
    await db.ospfInterface.delete({ where: { id } });
    return {
      data: { ok: true },
      audit: {
        action: "ospf_interface.delete",
        objectType: "ospf_interface",
        objectId: id,
        objectName: existing.interfaceName,
        before: existing,
      },
    };
  },
);
