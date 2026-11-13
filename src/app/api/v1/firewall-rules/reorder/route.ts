/**
 * POST /api/v1/firewall-rules/reorder — {orderedIds: number[]} full order write
 * (must be a permutation of the tenant's rule ids → 400 otherwise; renumbers
 * dense 1..N in one transaction — API_STANDARDS §8).
 */

import { route } from "@/lib/api/handler";
import { db } from "@/lib/db";
import { reorderBodySchema } from "@/lib/validators/firewall";
import { reorderRules } from "@/lib/firewall/rule-service";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "firewall", bodySchema: reorderBodySchema, section: "firewall" },
  async ({ auth, body }) => {
    await reorderRules(auth.tenantId, body.orderedIds);
    const rows = await db.firewallRule.findMany({
      where: { tenantId: auth.tenantId },
      orderBy: { position: "asc" },
      select: { id: true, position: true },
    });
    return {
      data: { rules: rows },
      audit: { action: "rule.reorder", objectType: "firewall_rule", objectName: `${body.orderedIds.length} rules` },
    };
  },
);
