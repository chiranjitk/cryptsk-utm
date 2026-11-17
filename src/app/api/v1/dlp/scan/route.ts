/**
 * POST /api/v1/dlp/scan — Phase 3 §3.3 protocol-aware scan entry point.
 * {protocol, sourceIp, userName?, text, fileExtension?} → enabled policies
 * scoped to the protocol run their patterns (keyword Aho-Corasick + regex),
 * DlpIncident rows are created with the policy's action and engine-redacted
 * excerpts; notifyUser + block/quarantine also raises a Notification.
 * Audits `dlp.scan` (scan is a mutation — it writes incidents).
 */

import { route } from "@/lib/api/handler";
import { dlpScanSchema } from "@/lib/validators/dlp";
import { scanTenant } from "@/lib/dlp/service";

export const dynamic = "force-dynamic";

export const POST = route({ area: "dlp", bodySchema: dlpScanSchema }, async ({ auth, body, ip }) => {
  const outcome = await scanTenant(auth.tenantId, { ...body, sourceIp: body.sourceIp || ip });
  return {
    data: outcome,
    audit: {
      action: "dlp.scan",
      objectType: "dlp_incident",
      objectName: `${body.protocol}:${body.sourceIp}`,
      after: { incidents: outcome.incidents, severity: outcome.severity },
    },
  };
});
