/**
 * GET /api/v1/dlp/stats — Phase 3 §3.3 console strip aggregates: incident
 * totals, severity/status breakdowns, pattern/policy counts and the 7-day
 * per-day incident trend (prisma groupBy / count).
 */

import { route } from "@/lib/api/handler";
import { getStats } from "@/lib/dlp/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "dlp" }, async ({ auth }) => {
  return { data: await getStats(auth.tenantId) };
});
