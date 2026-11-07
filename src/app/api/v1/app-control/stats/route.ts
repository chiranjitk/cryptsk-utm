/**
 * App control stats (M18 §2.2.6) — 24h allowed/blocked/limited counters, top 5
 * apps by log volume (with summed bytes) and per-rule hit counts.
 */

import { route } from "@/lib/api/handler";
import { getStats } from "@/app/api/v1/app-control/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "app_control" }, async ({ auth }) => {
  return { data: await getStats(auth.tenantId) };
});
