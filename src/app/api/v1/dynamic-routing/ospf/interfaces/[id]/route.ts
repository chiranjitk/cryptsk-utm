/**
 * OSPF interface item (M19 §2.6) — update / delete, audit
 * `ospf_interface.update|delete`. Partial updates merge with the stored row
 * and re-run the cross-field dead ≥ 2×hello rule (merge-then-revalidate).
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
    // merge-then-revalidate (mirrors ipv6/shared.ts updateNat66Rule): the
    // zod schema alone can't see cross-field pairs spanning patch + row
    const mergedHello = body.helloSec ?? existing.helloSec;
    const mergedDead = body.deadSec ?? existing.deadSec;
    if (mergedDead < 2 * mergedHello) {
      throw ApiError.validation("OSPF interface update failed validation", {
        fieldErrors: { deadSec: ["dead interval must be at least 2× hello"] },
      });
    }
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
