/**
 * GET  /api/v1/schedule-objects — list
 * POST /api/v1/schedule-objects — create (always/recurring/onetime)
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { fwListQuery, scheduleObjectBodySchema } from "@/lib/validators/firewall";
import { shapeScheduleObject } from "@/lib/firewall/shapes";

export const dynamic = "force-dynamic";

export const GET = route({ area: "firewall", querySchema: fwListQuery }, async ({ auth, query }) => {
  const q = (query.q ?? query.search ?? "").trim();
  const where = { tenantId: auth.tenantId, ...(q ? { name: { contains: q } } : {}) };
  const [total, rows] = await Promise.all([
    db.scheduleObject.count({ where }),
    db.scheduleObject.findMany({
      where,
      orderBy: { name: "asc" },
      skip: (query.page - 1) * query.limit,
      take: query.limit,
    }),
  ]);
  return {
    data: rows.map(shapeScheduleObject),
    meta: { page: query.page, limit: query.limit, total, totalPages: Math.max(1, Math.ceil(total / query.limit)) },
  };
});

export const POST = route(
  { area: "firewall", bodySchema: scheduleObjectBodySchema, section: "firewall" },
  async ({ auth, body }) => {
    const dup = await db.scheduleObject.findFirst({ where: { tenantId: auth.tenantId, name: body.name } });
    if (dup) throw ApiError.conflict(`Schedule object '${body.name}' already exists`);
    const row = await db.scheduleObject.create({
      data: {
        tenantId: auth.tenantId,
        name: body.name,
        type: body.type,
        recurrence: body.recurrence ? JSON.stringify(body.recurrence) : null,
        startsAt: body.startsAt ? new Date(body.startsAt) : null,
        endsAt: body.endsAt ? new Date(body.endsAt) : null,
        timezone: body.timezone,
      },
    });
    return {
      data: shapeScheduleObject(row),
      audit: { action: "schedule_object.create", objectType: "schedule_object", objectId: row.id, objectName: row.name, after: { ...row } },
    };
  },
);
