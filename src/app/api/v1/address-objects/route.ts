/**
 * GET  /api/v1/address-objects — list (?q=&type=&page=&limit=)
 * POST /api/v1/address-objects — create (409 duplicate name; value grammar
 * validated per type by zod).
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { addressObjectBodySchema, fwListQuery } from "@/lib/validators/firewall";
import { shapeAddressObject } from "@/lib/firewall/shapes";

export const dynamic = "force-dynamic";

export const GET = route({ area: "firewall", querySchema: fwListQuery }, async ({ auth, query }) => {
  const q = (query.q ?? query.search ?? "").trim();
  const where = {
    tenantId: auth.tenantId,
    ...(q ? { OR: [{ name: { contains: q } }, { value: { contains: q } }] } : {}),
    ...(query.type ? { type: query.type } : {}),
  };
  const [total, rows] = await Promise.all([
    db.addressObject.count({ where }),
    db.addressObject.findMany({
      where,
      orderBy: { name: "asc" },
      skip: (query.page - 1) * query.limit,
      take: query.limit,
    }),
  ]);
  return {
    data: rows.map(shapeAddressObject),
    meta: { page: query.page, limit: query.limit, total, totalPages: Math.max(1, Math.ceil(total / query.limit)) },
  };
});

export const POST = route(
  { area: "firewall", bodySchema: addressObjectBodySchema, section: "firewall" },
  async ({ auth, body }) => {
    const dup = await db.addressObject.findFirst({ where: { tenantId: auth.tenantId, name: body.name } });
    if (dup) throw ApiError.conflict(`Address object '${body.name}' already exists`);
    const row = await db.addressObject.create({
      data: {
        tenantId: auth.tenantId,
        name: body.name,
        type: body.type,
        value: body.value.trim(),
        description: body.description ?? null,
      },
    });
    return {
      data: shapeAddressObject(row),
      audit: { action: "address_object.create", objectType: "address_object", objectId: row.id, objectName: row.name, after: { ...row } },
    };
  },
);
