/**
 * GET /api/v1/threat-intel/stats — M13 console strip aggregates:
 * IOC totals, severity/category breakdowns, active feeds, auto-block
 * rules and 24h hit count (prisma groupBy / count).
 */

import { route } from "@/lib/api/handler";
import { getStats } from "@/lib/threat-intel/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "threat_intel" }, async ({ auth }) => {
  return { data: await getStats(auth.tenantId) };
});
