/**
 * GET/PUT/DELETE /api/v1/address-groups/{id}
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { addressGroupBodySchema, idParamSchema } from "@/lib/validators/firewall";
import { shapeNamedWithMembers } from "@/lib/firewall/shapes";
import { addressGroupReferences } from "@/lib/firewall/refs";

export const dynamic = "force-dynamic";

async function findRow(tenantId: number, id: number) {
  const row = await db.addressGroup.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound(`Address group ${id} not found`);
  return row;
}

export const GET = route({ area: "firewall" }, async ({ auth, params }) => {
  const { id } = idParamSchema.parse(params);
  return { data: shapeNamedWithMembers(await findRow(auth.tenantId, id)) };
});

export const PUT = route(
  { area: "firewall", bodySchema: addressGroupBodySchema, section: "firewall" },
  async ({ auth, params, body }) => {
    const { id } = idParamSchema.parse(params);
    const row = await findRow(auth.tenantId, id);
    if (body.name !== row.name) {
      const dup = await db.addressGroup.findFirst({ where: { tenantId: auth.tenantId, name: body.name } });
      if (dup) throw ApiError.conflict(`Address group '${body.name}' already exists`);
    }
    if (body.memberIds.length) {
      const found = await db.addressObject.count({ where: { tenantId: auth.tenantId, id: { in: body.memberIds } } });
      if (found < body.memberIds.length) {
        const all = await db.addressObject.findMany({ where: { tenantId: auth.tenantId }, select: { id: true } });
        const known = new Set(all.map((a) => a.id));
        throw ApiError.validation("Unknown member id in memberIds", {
          offendingIds: body.memberIds.filter((m) => !known.has(m)),
        });
      }
    }
    const updated = await db.addressGroup.update({
      where: { id: row.id },
      data: { name: body.name, memberIds: JSON.stringify(body.memberIds), description: body.description ?? null },
    });
    return {
      data: shapeNamedWithMembers(updated),
      audit: {
        action: "address_group.update",
        objectType: "address_group",
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
  const refs = await addressGroupReferences(auth.tenantId, row.id);
  if (refs.length) {
    throw ApiError.conflict(`Address group '${row.name}' is referenced by ${refs.length} rule(s)`, {
      referencedBy: refs,
    });
  }
  await db.addressGroup.delete({ where: { id: row.id } });
  return {
    data: { ok: true },
    audit: {
      action: "address_group.delete",
      objectType: "address_group",
      objectId: row.id,
      objectName: row.name,
      before: { ...row },
    },
  };
});
