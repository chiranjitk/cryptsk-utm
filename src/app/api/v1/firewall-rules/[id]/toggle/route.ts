/**
 * PATCH /api/v1/firewall-rules/{id}/toggle — {enabled}, optimistic from the UI.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { idParamSchema, toggleBodySchema } from "@/lib/validators/firewall";
import { shapeFirewallRule } from "@/lib/firewall/rule-shape";

export const dynamic = "force-dynamic";

export const PATCH = route(
  { area: "firewall", bodySchema: toggleBodySchema, section: "firewall" },
  async ({ auth, params, body }) => {
    const { id } = idParamSchema.parse(params);
    const row = await db.firewallRule.findFirst({ where: { id, tenantId: auth.tenantId } });
    if (!row) throw ApiError.notFound(`Firewall rule ${id} not found`);
    const updated = await db.firewallRule.update({ where: { id: row.id }, data: { enabled: body.enabled } });
    return {
      data: shapeFirewallRule(updated),
      audit: {
        action: "rule.toggle",
        objectType: "firewall_rule",
        objectId: row.id,
        objectName: row.name,
        before: { enabled: row.enabled },
        after: { enabled: updated.enabled },
      },
    };
  },
);
