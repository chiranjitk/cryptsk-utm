/** GET /api/v1/logs/stats?range=1h|24h|7d — LOCKED aggregate payload (M09 §3). */

import { route } from "@/lib/api/handler";
import { statsQuerySchema } from "@/lib/validators/logs";
import { getLogStats } from "@/lib/logs/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "reports", querySchema: statsQuerySchema }, async ({ auth, query }) => {
  return { data: await getLogStats(auth.tenantId, query.range) };
});
