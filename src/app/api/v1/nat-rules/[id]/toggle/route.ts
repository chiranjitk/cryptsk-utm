/**
 * PATCH /api/v1/nat-rules/{id}/toggle — {enabled}, optimistic from the UI.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { idParamSchema, toggleBodySchema } from "@/lib/validators/firewall";
import { shapeNatRule } from "@/lib/firewall/rule-shape";

export const dynamic = "force-dynamic";

export const PATCH = route(
  { area: "firewall", bodySchema: toggleBodySchema, section: "nat" },
  async ({ auth, params, body }) => {
    const { id } = idParamSchema.parse(params);
    const row = await db.natRule.findFirst({ where: { id, tenantId: auth.tenantId } });
    if (!row) throw ApiError.notFound(`NAT rule ${id} not found`);
    const updated = await db.natRule.update({ where: { id: row.id }, data: { enabled: body.enabled } });
    return {
      data: shapeNatRule(updated),
      audit: {
        action: "nat_rule.toggle",
        objectType: "nat_rule",
        objectId: row.id,
        objectName: row.name ?? `#${row.id}`,
        before: { enabled: row.enabled },
        after: { enabled: updated.enabled },
      },
    };
  },
);
