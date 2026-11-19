/**
 * GET /api/v1/ztna/stats — console strip aggregates (Phase 4 §4.4):
 * application/policy counts, compliance pie data (latest posture verdict per
 * device), stale re-check count and recent denied access evaluations.
 */

import { route } from "@/lib/api/handler";
import { getZtnaStats } from "@/lib/ztna/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "ztna" }, async ({ auth }) => {
  return { data: await getZtnaStats(auth.tenantId) };
});
