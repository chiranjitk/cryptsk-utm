/**
 * POST /api/v1/firewall-rules/{id}/hits/reset — zero per-rule counters (audited;
 * there is intentionally no "reset all" endpoint in Phase 1 — M03 §5).
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { idParamSchema } from "@/lib/validators/firewall";

export const dynamic = "force-dynamic";

export const POST = route({ area: "firewall", section: "firewall" }, async ({ auth, params }) => {
  const { id } = idParamSchema.parse(params);
  const row = await db.firewallRule.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!row) throw ApiError.notFound(`Firewall rule ${id} not found`);
  await db.firewallRule.update({ where: { id: row.id }, data: { hitCount: 0, lastHitAt: null } });
  return {
    data: { id: row.id, hitCount: 0, lastHitAt: null },
    audit: {
      action: "rule.hits_reset",
      objectType: "firewall_rule",
      objectId: row.id,
      objectName: row.name,
      before: { hitCount: row.hitCount, lastHitAt: row.lastHitAt },
      after: { hitCount: 0, lastHitAt: null },
    },
  };
});
