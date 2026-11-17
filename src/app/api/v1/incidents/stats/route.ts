/**
 * GET /api/v1/incidents/stats — SOC strip aggregates (Phase 3 §3.5):
 * open incidents by severity, created-in-last-7-days count and the mean
 * time to resolve (hours, createdAt → resolvedAt over resolved incidents).
 */

import { route } from "@/lib/api/handler";
import { getStats } from "@/lib/incidents/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "ips_events" }, async ({ auth }) => {
  return { data: await getStats(auth.tenantId) };
});
