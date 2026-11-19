/** GET /api/v1/logs/stats?range=1h|24h|7d — LOCKED aggregate payload (M09 §3). */

import { route } from "@/lib/api/handler";
import { statsQuerySchema } from "@/lib/validators/logs";
import { getLogStats } from "@/lib/logs/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "logs", querySchema: statsQuerySchema }, async ({ auth, query }) => {
  // audit fix L25 — the stats strip is a log-surface read: area `logs`
  // (helpdesk holds logs.read, not reports.read — the previous `reports`
  // area silently broke the helpdesk view while every sibling log read
  // uses `logs`).
  return { data: await getLogStats(auth.tenantId, query.range) };
});
