/**
 * GET/PUT/DELETE /api/v1/address-objects/{id} — 409 on delete when referenced
 * by firewall/NAT rules (details.referencedBy = [{ruleName, ruleType}]).
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { addressObjectBodySchema, idParamSchema } from "@/lib/validators/firewall";
import { shapeAddressObject } from "@/lib/firewall/shapes";
import { addressObjectReferences } from "@/lib/firewall/refs";

export const dynamic = "force-dynamic";

async function findRow(tenantId: number, id: number) {
  const row = await db.addressObject.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound(`Address object ${id} not found`);
  return row;
}

export const GET = route({ area: "firewall" }, async ({ auth, params }) => {
  const { id } = idParamSchema.parse(params);
  return { data: shapeAddressObject(await findRow(auth.tenantId, id)) };
});

export const PUT = route(
  { area: "firewall", bodySchema: addressObjectBodySchema, section: "firewall" },
  async ({ auth, params, body }) => {
    const { id } = idParamSchema.parse(params);
    const row = await findRow(auth.tenantId, id);
    if (body.name !== row.name) {
      const dup = await db.addressObject.findFirst({ where: { tenantId: auth.tenantId, name: body.name } });
      if (dup) throw ApiError.conflict(`Address object '${body.name}' already exists`);
    }
    const updated = await db.addressObject.update({
      where: { id: row.id },
      data: { name: body.name, type: body.type, value: body.value.trim(), description: body.description ?? null },
    });
    return {
      data: shapeAddressObject(updated),
      audit: {
        action: "address_object.update",
        objectType: "address_object",
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
  const refs = await addressObjectReferences(row.id);
  if (refs.length) {
    throw ApiError.conflict(`Address object '${row.name}' is referenced by ${refs.length} rule(s)`, {
      referencedBy: refs,
    });
  }
  await db.addressObject.delete({ where: { id: row.id } });
  return {
    data: { ok: true },
    audit: {
      action: "address_object.delete",
      objectType: "address_object",
      objectId: row.id,
      objectName: row.name,
      before: { ...row },
    },
  };
});
