/**
 * PATCH /api/v1/pbr-rules/{id}/toggle — {enabled}, optimistic from the UI
 * (row enable switch, M02 §4 tab 2).
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { idParamSchema, toggleBodySchema } from "@/lib/validators/network";
import { shapePbrRule } from "@/lib/network/shapes";

export const dynamic = "force-dynamic";

export const PATCH = route(
  { area: "network", bodySchema: toggleBodySchema, section: "routing" },
  async ({ auth, params, body }) => {
    const { id } = idParamSchema.parse(params);
    const row = await db.pbrRule.findFirst({ where: { id, tenantId: auth.tenantId } });
    if (!row) throw ApiError.notFound(`PBR rule ${id} not found`);

    const updated = await db.pbrRule.update({ where: { id: row.id }, data: { enabled: body.enabled } });
    return {
      data: shapePbrRule(updated),
      audit: {
        action: "pbr.toggle",
        objectType: "pbr_rule",
        objectId: row.id,
        objectName: row.name,
        before: { enabled: row.enabled },
        after: { enabled: updated.enabled },
      },
    };
  },
);
