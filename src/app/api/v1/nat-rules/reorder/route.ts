/**
 * POST /api/v1/nat-rules/reorder — {orderedIds: number[]} full order write.
 */

import { route } from "@/lib/api/handler";
import { db } from "@/lib/db";
import { reorderBodySchema } from "@/lib/validators/firewall";
import { reorderNatRules } from "@/lib/firewall/nat-service";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "firewall", bodySchema: reorderBodySchema, section: "nat" },
  async ({ auth, body }) => {
    await reorderNatRules(auth.tenantId, body.orderedIds);
    const rows = await db.natRule.findMany({
      where: { tenantId: auth.tenantId },
      orderBy: { position: "asc" },
      select: { id: true, position: true },
    });
    return {
      data: { rules: rows },
      audit: { action: "nat_rule.reorder", objectType: "nat_rule", objectName: `${body.orderedIds.length} rules` },
    };
  },
);
