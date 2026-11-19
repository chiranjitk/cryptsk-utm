/**
 * POST /api/v1/config-anomaly/scan — spec §4.5 rule-based config anomaly pass
 * (ML variant explicitly deferred): runs all six firewall detectors over the
 * tenant's enabled rules + objects and diffs against persisted findings per
 * the dedupe window contract. All body options are optional
 * ({wanZoneIds?, requireWanLogging?}) — POST "{}" for pure defaults (JSON
 * body required, matching every other POST route in the handler contract).
 */

import { route } from "@/lib/api/handler";
import { configAnomalyScanSchema } from "@/lib/validators/config-anomaly";
import { scanConfigAnomalies } from "@/lib/firewall/anomaly-service";

export const dynamic = "force-dynamic";

export const POST = route({ area: "config_anomaly", bodySchema: configAnomalyScanSchema }, async ({ auth, body }) => {
  const summary = await scanConfigAnomalies(auth.tenantId, {
    wanZoneIds: body.wanZoneIds,
    requireWanLogging: body.requireWanLogging,
  });
  return {
    data: summary,
    audit: {
      action: "config_anomaly.scan",
      objectType: "config_anomaly_finding",
      after: {
        detected: summary.detected,
        newOpen: summary.newOpen,
        autoResolved: summary.autoResolved,
        byKind: summary.byKind,
      },
    },
  };
});
