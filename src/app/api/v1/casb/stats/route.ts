/**
 * GET /api/v1/casb/stats — CASB console strip aggregates (Phase 4 §4.3):
 * discovery totals by verdict, top shadow apps and top client talkers
 * (prisma groupBy, tenant-scoped).
 */

import { route } from "@/lib/api/handler";
import { getCasbStats } from "@/lib/casb/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "casb" }, async ({ auth }) => {
  return { data: await getCasbStats(auth.tenantId) };
});
