/**
 * /api/v1/sites/stats — fleet strip aggregates (Phase 4 §4.1): total sites,
 * totals by site status, per-role counts and the deployment volume of the
 * last 7 days.
 */

import { route } from "@/lib/api/handler";
import { getSiteStats } from "@/lib/sites/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "sites" }, async ({ auth }) => {
  return { data: await getSiteStats(auth.tenantId) };
});
