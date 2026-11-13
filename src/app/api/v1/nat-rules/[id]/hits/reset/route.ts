/**
 * POST /api/v1/nat-rules/{id}/hits/reset — zero per-rule counters (audited;
 * mirrors /firewall-rules/{id}/hits/reset).
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { idParamSchema } from "@/lib/validators/firewall";

export const dynamic = "force-dynamic";

export const POST = route({ area: "firewall", section: "nat" }, async ({ auth, params }) => {
  const { id } = idParamSchema.parse(params);
  const row = await db.natRule.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!row) throw ApiError.notFound(`NAT rule ${id} not found`);
  await db.natRule.update({ where: { id: row.id }, data: { hitCount: 0, lastHitAt: null } });
  return {
    data: { id: row.id, hitCount: 0, lastHitAt: null },
    audit: {
      action: "nat_rule.hits_reset",
      objectType: "nat_rule",
      objectId: row.id,
      objectName: row.name ?? `#${row.id}`,
      before: { hitCount: row.hitCount, lastHitAt: row.lastHitAt },
      after: { hitCount: 0, lastHitAt: null },
    },
  };
});
