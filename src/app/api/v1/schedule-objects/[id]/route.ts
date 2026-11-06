/**
 * GET/PUT/DELETE /api/v1/schedule-objects/{id} — delete is RESTRICT while any
 * firewall rule still points at the schedule (409 with rule names).
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { idParamSchema, scheduleObjectBodySchema } from "@/lib/validators/firewall";
import { shapeScheduleObject } from "@/lib/firewall/shapes";
import { scheduleReferences } from "@/lib/firewall/refs";

export const dynamic = "force-dynamic";

async function findRow(tenantId: number, id: number) {
  const row = await db.scheduleObject.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound(`Schedule object ${id} not found`);
  return row;
}

export const GET = route({ area: "firewall" }, async ({ auth, params }) => {
  const { id } = idParamSchema.parse(params);
  return { data: shapeScheduleObject(await findRow(auth.tenantId, id)) };
});

export const PUT = route(
  { area: "firewall", bodySchema: scheduleObjectBodySchema, section: "firewall" },
  async ({ auth, params, body }) => {
    const { id } = idParamSchema.parse(params);
    const row = await findRow(auth.tenantId, id);
    if (body.name !== row.name) {
      const dup = await db.scheduleObject.findFirst({ where: { tenantId: auth.tenantId, name: body.name } });
      if (dup) throw ApiError.conflict(`Schedule object '${body.name}' already exists`);
    }
    const updated = await db.scheduleObject.update({
      where: { id: row.id },
      data: {
        name: body.name,
        type: body.type,
        recurrence: body.recurrence ? JSON.stringify(body.recurrence) : null,
        startsAt: body.startsAt ? new Date(body.startsAt) : null,
        endsAt: body.endsAt ? new Date(body.endsAt) : null,
        timezone: body.timezone,
      },
    });
    return {
      data: shapeScheduleObject(updated),
      audit: {
        action: "schedule_object.update",
        objectType: "schedule_object",
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
  const refs = await scheduleReferences(row.id);
  if (refs.length) {
    throw ApiError.conflict(`Schedule '${row.name}' is attached to ${refs.length} rule(s) — detach them first`, {
      referencedBy: refs,
    });
  }
  await db.scheduleObject.delete({ where: { id: row.id } });
  return {
    data: { ok: true },
    audit: {
      action: "schedule_object.delete",
      objectType: "schedule_object",
      objectId: row.id,
      objectName: row.name,
      before: { ...row },
    },
  };
});
