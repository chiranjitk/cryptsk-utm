/**
 * GET/PUT/DELETE /api/v1/firewall-rules/{id} — detail, replace, delete
 * (delete renumbers the remaining rules dense 1..N in one transaction).
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { firewallRuleBodySchema, idParamSchema } from "@/lib/validators/firewall";
import { shapeFirewallRule } from "@/lib/firewall/rule-shape";
import { updateRule } from "@/lib/firewall/rule-service";
import { renumberFirewallRules } from "@/lib/firewall/positions";

export const dynamic = "force-dynamic";

export const GET = route({ area: "firewall" }, async ({ auth, params }) => {
  const { id } = idParamSchema.parse(params);
  const row = await db.firewallRule.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!row) throw ApiError.notFound(`Firewall rule ${id} not found`);
  return { data: shapeFirewallRule(row) };
});

export const PUT = route(
  { area: "firewall", bodySchema: firewallRuleBodySchema, section: "firewall" },
  async ({ auth, params, body }) => {
    const { id } = idParamSchema.parse(params);
    const before = await db.firewallRule.findFirst({ where: { id, tenantId: auth.tenantId } });
    if (!before) throw ApiError.notFound(`Firewall rule ${id} not found`);
    await updateRule(auth.tenantId, id, body);
    const after = await db.firewallRule.findUniqueOrThrow({ where: { id } });
    return {
      data: shapeFirewallRule(after),
      audit: {
        action: "rule.update",
        objectType: "firewall_rule",
        objectId: id,
        objectName: before.name,
        before: shapeFirewallRule(before),
        after: shapeFirewallRule(after),
      },
    };
  },
);

export const DELETE = route({ area: "firewall", section: "firewall" }, async ({ auth, params }) => {
  const { id } = idParamSchema.parse(params);
  const row = await db.firewallRule.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!row) throw ApiError.notFound(`Firewall rule ${id} not found`);

  await db.$transaction(async (tx) => {
    await tx.firewallRule.delete({ where: { id: row.id } });
    await renumberFirewallRules(tx as unknown as Parameters<typeof renumberFirewallRules>[0], auth.tenantId);
  });

  return {
    data: { ok: true },
    audit: {
      action: "rule.delete",
      objectType: "firewall_rule",
      objectId: row.id,
      objectName: row.name,
      before: shapeFirewallRule(row),
    },
  };
});
