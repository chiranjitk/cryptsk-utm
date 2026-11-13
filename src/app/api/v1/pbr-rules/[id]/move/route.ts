/**
 * POST /api/v1/pbr-rules/{id}/move — reorder a policy route by position.
 * Swaps transactionally with the occupant of the target slot (position 1..N
 * clamped by aggregation), so the evaluation order stays dense (1..N).
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { idParamSchema, pbrMoveBody } from "@/lib/validators/network";
import { shapePbrRule } from "@/lib/network/shapes";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "network", bodySchema: pbrMoveBody, section: "routing" },
  async ({ auth, params, body }) => {
    const { id } = idParamSchema.parse(params);
    const rows = await db.pbrRule.findMany({ where: { tenantId: auth.tenantId }, orderBy: { position: "asc" } });
    const me = rows.find((r) => r.id === id);
    if (!me) throw ApiError.notFound(`PBR rule ${id} not found`);

    const max = rows.reduce((m, r) => Math.max(m, r.position), 0);
    const target = Math.min(body.position, max);
    const occupant = rows.find((r) => r.position === target);
    if (occupant && occupant.id === me.id) {
      return { data: { moved: false, rule: shapePbrRule(me) } };
    }

    await db.$transaction(async (tx) => {
      if (occupant) {
        await tx.pbrRule.update({ where: { id: occupant.id }, data: { position: me.position } });
      }
      await tx.pbrRule.update({ where: { id: me.id }, data: { position: target } });
    });

    const updated = await db.pbrRule.findUnique({ where: { id } });
    return {
      data: { moved: true, rule: updated ? shapePbrRule(updated) : null, swappedWith: occupant?.name ?? null },
      audit: {
        action: "pbr.move",
        objectType: "pbr_rule",
        objectId: id,
        objectName: me.name,
        before: { position: me.position },
        after: { position: target, swappedWith: occupant?.name ?? null },
      },
    };
  },
);
