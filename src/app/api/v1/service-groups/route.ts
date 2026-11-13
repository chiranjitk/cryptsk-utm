/**
 * GET  /api/v1/service-groups — list
 * POST /api/v1/service-groups — create (memberIds ⊆ service_objects)
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { fwListQuery, serviceGroupBodySchema } from "@/lib/validators/firewall";
import { shapeNamedWithMembers } from "@/lib/firewall/shapes";

export const dynamic = "force-dynamic";

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

export const GET = route({ area: "firewall", querySchema: fwListQuery }, async ({ auth, query }) => {
  const q = (query.q ?? query.search ?? "").trim();
  const where = { tenantId: auth.tenantId, ...(q ? { name: { contains: q } } : {}) };
  const [total, rows] = await Promise.all([
    db.serviceGroup.count({ where }),
    db.serviceGroup.findMany({
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
  { area: "firewall", bodySchema: serviceGroupBodySchema, section: "firewall" },
  async ({ auth, body }) => {
    const dup = await db.serviceGroup.findFirst({ where: { tenantId: auth.tenantId, name: body.name } });
    if (dup) throw ApiError.conflict(`Service group '${body.name}' already exists`);
    await assertMembers(auth.tenantId, body.memberIds);
    const row = await db.serviceGroup.create({
      data: {
        tenantId: auth.tenantId,
        name: body.name,
        memberIds: JSON.stringify(body.memberIds),
        description: body.description ?? null,
      },
    });
    return {
      data: shapeNamedWithMembers(row),
      audit: { action: "service_group.create", objectType: "service_group", objectId: row.id, objectName: row.name, after: { ...row } },
    };
  },
);
