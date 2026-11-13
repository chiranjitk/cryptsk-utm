/**
 * GET /api/v1/nat-rules/{id}/hits — current hit counters for a NAT rule
 * (kernel `nat:<id>:<name>` comments synced by /firewall-rules/os sync-hits).
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { idParamSchema } from "@/lib/validators/firewall";

export const dynamic = "force-dynamic";

export const GET = route({ area: "firewall" }, async ({ auth, params }) => {
  const { id } = idParamSchema.parse(params);
  const row = await db.natRule.findFirst({
    where: { id, tenantId: auth.tenantId },
    select: { id: true, name: true, hitCount: true, lastHitAt: true },
  });
  if (!row) throw ApiError.notFound(`NAT rule ${id} not found`);
  return { data: { id: row.id, name: row.name, hitCount: row.hitCount, lastHitAt: row.lastHitAt } };
});
