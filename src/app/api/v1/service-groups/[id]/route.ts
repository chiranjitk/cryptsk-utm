/**
 * GET/PUT/DELETE /api/v1/service-groups/{id}
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { idParamSchema, serviceGroupBodySchema } from "@/lib/validators/firewall";
import { shapeNamedWithMembers } from "@/lib/firewall/shapes";
import { serviceGroupReferences } from "@/lib/firewall/refs";

export const dynamic = "force-dynamic";

async function findRow(tenantId: number, id: number) {
  const row = await db.serviceGroup.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound(`Service group ${id} not found`);
  return row;
}

async function assertMembers(tenantId: number, memberIds: number[]) {
  if (!memberIds.length) return;
  const found = await db.serviceObject.count({ where: { tenantId, id: { in: memberIds } } });
  if (found < memberIds.length) {
    const all = await db.serviceObject.findMany({ where: { tenantId }, select: { id: true } });
    const known = new Set(all.map((s) => s.id));
    throw ApiError.validation("Unknown member id in memberIds", {
      offendingIds: memberIds.filter((m) => !known.has(m)),
    });
  }
}

export const GET = route({ area: "firewall" }, async ({ auth, params }) => {
  const { id } = idParamSchema.parse(params);
  return { data: shapeNamedWithMembers(await findRow(auth.tenantId, id)) };
});

export const PUT = route(
  { area: "firewall", bodySchema: serviceGroupBodySchema, section: "firewall" },
  async ({ auth, params, body }) => {
    const { id } = idParamSchema.parse(params);
    const row = await findRow(auth.tenantId, id);
    if (body.name !== row.name) {
      const dup = await db.serviceGroup.findFirst({ where: { tenantId: auth.tenantId, name: body.name } });
      if (dup) throw ApiError.conflict(`Service group '${body.name}' already exists`);
    }
    await assertMembers(auth.tenantId, body.memberIds);
    const updated = await db.serviceGroup.update({
      where: { id: row.id },
      data: { name: body.name, memberIds: JSON.stringify(body.memberIds), description: body.description ?? null },
    });
    return {
      data: shapeNamedWithMembers(updated),
      audit: {
        action: "service_group.update",
        objectType: "service_group",
        objectId: row.id,
        objectName: row.name,
        before: { ...row },
        after: { ...updated },
      },
    };
  },
);

export const DELETE = route({ area: "firewall", section: "firewall" }, async ({ auth, params }) => {
  const { id } = idParamSchema.parse(params);
  const row = await findRow(auth.tenantId, id);
  const refs = await serviceGroupReferences(row.id);
  if (refs.length) {
    throw ApiError.conflict(`Service group '${row.name}' is referenced by ${refs.length} rule(s)`, {
      referencedBy: refs,
    });
  }
  await db.serviceGroup.delete({ where: { id: row.id } });
  return {
    data: { ok: true },
    audit: {
      action: "service_group.delete",
      objectType: "service_group",
      objectId: row.id,
      objectName: row.name,
      before: { ...row },
    },
  };
});
