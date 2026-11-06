/**
 * GET  /api/v1/service-objects — list (?q=&page=&limit=)
 * POST /api/v1/service-objects — create (tcp/udp/icmp/any + port-list grammar)
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { fwListQuery, serviceObjectBodySchema } from "@/lib/validators/firewall";
import { shapeServiceObject } from "@/lib/firewall/shapes";

export const dynamic = "force-dynamic";

export const GET = route({ area: "firewall", querySchema: fwListQuery }, async ({ auth, query }) => {
  const q = (query.q ?? query.search ?? "").trim();
  const where = {
    tenantId: auth.tenantId,
    ...(q ? { OR: [{ name: { contains: q } }, { dstPort: { contains: q } }] } : {}),
  };
  const [total, rows] = await Promise.all([
    db.serviceObject.count({ where }),
    db.serviceObject.findMany({
      where,
      orderBy: { name: "asc" },
      skip: (query.page - 1) * query.limit,
      take: query.limit,
    }),
  ]);
  return {
    data: rows.map(shapeServiceObject),
    meta: { page: query.page, limit: query.limit, total, totalPages: Math.max(1, Math.ceil(total / query.limit)) },
  };
});

export const POST = route(
  { area: "firewall", bodySchema: serviceObjectBodySchema, section: "firewall" },
  async ({ auth, body }) => {
    const dup = await db.serviceObject.findFirst({ where: { tenantId: auth.tenantId, name: body.name } });
    if (dup) throw ApiError.conflict(`Service object '${body.name}' already exists`);
    const row = await db.serviceObject.create({
      data: {
        tenantId: auth.tenantId,
        name: body.name,
        protocol: body.protocol,
        srcPort: body.srcPort ?? null,
        dstPort: body.dstPort ?? null,
        icmpType: body.icmpType ?? null,
        icmpCode: body.icmpCode ?? null,
        description: body.description ?? null,
      },
    });
    return {
      data: shapeServiceObject(row),
      audit: { action: "service_object.create", objectType: "service_object", objectId: row.id, objectName: row.name, after: { ...row } },
    };
  },
);
