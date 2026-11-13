/**
 * WAF log list (M17 §2.4.5) — paged-lite descending feed:
 * GET /api/v1/waf/logs?vhostId?&action?&limit=100 (default 100, max 500).
 */

import { route } from "@/lib/api/handler";
import { db } from "@/lib/db";
import { wafLogQuerySchema } from "@/lib/validators/waf";
import { shapeLog } from "@/app/api/v1/waf/shared";

export const dynamic = "force-dynamic";

export const GET = route({ area: "waf", querySchema: wafLogQuerySchema }, async ({ auth, query }) => {
  const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000); // keep the feed bounded
  const [rows, vhosts] = await Promise.all([
    db.wafLog.findMany({
      where: {
        tenantId: auth.tenantId,
        createdAt: { gte: since },
        ...(query.vhostId !== undefined ? { vhostId: query.vhostId } : {}),
        ...(query.action ? { action: query.action } : {}),
      },
      orderBy: { createdAt: "desc" },
      take: query.limit,
    }),
    db.wafVhost.findMany({ where: { tenantId: auth.tenantId }, select: { id: true, hostname: true } }),
  ]);
  const vhostNames = new Map(vhosts.map((v) => [v.id, v.hostname]));
  return { data: rows.map((r) => shapeLog(r, vhostNames)) };
});
