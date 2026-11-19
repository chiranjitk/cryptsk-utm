/**
 * GET /api/v1/soar/stats — SOAR strip aggregates (Phase 4 §4.6): playbook
 * totals + enabled, run outcome counters with success rate over terminal
 * runs, runs in the last 7 days, and playbook counts per trigger kind.
 */

import { route } from "@/lib/api/handler";
import { getStats } from "@/lib/soar/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "soar" }, async ({ auth }) => {
  return { data: await getStats(auth.tenantId) };
});
