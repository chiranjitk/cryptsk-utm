/**
 * GET  /api/v1/address-groups — list (member ids resolved; ?q=&page=&limit=)
 * POST /api/v1/address-groups — create; every memberIds id must exist in
 * address_objects (400 otherwise; groups are flat — ER_DIAGRAM §3).
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { addressGroupBodySchema, fwListQuery } from "@/lib/validators/firewall";
import { shapeNamedWithMembers } from "@/lib/firewall/shapes";

export const dynamic = "force-dynamic";

export const GET = route({ area: "firewall", querySchema: fwListQuery }, async ({ auth, query }) => {
  const q = (query.q ?? query.search ?? "").trim();
  const where = { tenantId: auth.tenantId, ...(q ? { name: { contains: q } } : {}) };
  const [total, rows] = await Promise.all([
    db.addressGroup.count({ where }),
    db.addressGroup.findMany({
      where,
      orderBy: { name: "asc" },
      skip: (query.page - 1) * query.limit,
      take: query.limit,
    }),
  ]);
  return {
    data: rows.map(shapeNamedWithMembers),
    meta: { page: query.page, limit: query.limit, total, totalPages: Math.max(1, Math.ceil(total / query.limit)) },
  };
});

export const POST = route(
  { area: "firewall", bodySchema: addressGroupBodySchema, section: "firewall" },
  async ({ auth, body }) => {
    const dup = await db.addressGroup.findFirst({ where: { tenantId: auth.tenantId, name: body.name } });
    if (dup) throw ApiError.conflict(`Address group '${body.name}' already exists`);
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
    const row = await db.addressGroup.create({
      data: {
        tenantId: auth.tenantId,
        name: body.name,
        memberIds: JSON.stringify(body.memberIds),
        description: body.description ?? null,
      },
    });
    return {
      data: shapeNamedWithMembers(row),
      audit: { action: "address_group.create", objectType: "address_group", objectId: row.id, objectName: row.name, after: { ...row } },
    };
  },
);
