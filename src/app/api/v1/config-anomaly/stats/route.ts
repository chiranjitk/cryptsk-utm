/**
 * GET /api/v1/config-anomaly/stats — console strip aggregates (spec §4.5
 * rule-based pass): open counts by kind and severity, plus lastScanAt = max
 * detectedAt over ALL rows (the last scan that produced at least one finding).
 */

import { route } from "@/lib/api/handler";
import { statsFindings } from "@/lib/firewall/anomaly-service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "config_anomaly" }, async ({ auth }) => {
  return { data: await statsFindings(auth.tenantId) };
});
