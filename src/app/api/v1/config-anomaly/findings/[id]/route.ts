/**
 * PATCH /api/v1/config-anomaly/findings/[id] — triage workflow (spec §4.5):
 * resolved | ignored ONLY (no reopen verb — a still-real subject re-opens
 * implicitly when a later scan re-detects it under triage suppression rules).
 * Resolved stamps resolvedAt; ignored clears it (resolvedAt set iff resolved).
 */

import { route, numericId } from "@/lib/api/handler";
import { configAnomalyFindingPatchSchema } from "@/lib/validators/config-anomaly";
import { updateFindingStatus } from "@/lib/firewall/anomaly-service";

export const dynamic = "force-dynamic";

export const PATCH = route(
  { area: "config_anomaly", bodySchema: configAnomalyFindingPatchSchema },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const updated = await updateFindingStatus(auth.tenantId, id, body.status);
    return {
      data: updated,
      audit: {
        action: "config_anomaly.finding.status",
        objectType: "config_anomaly_finding",
        objectId: id,
        after: { status: updated.status, resolvedAt: updated.resolvedAt },
      },
    };
  },
);
