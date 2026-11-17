/** DLP incident status (Phase 3 §3.3 workflow) — PATCH {status}, audit `dlp.incident.status`. */

import { route, numericId } from "@/lib/api/handler";
import { dlpIncidentStatusUpdateSchema } from "@/lib/validators/dlp";
import { updateIncidentStatus } from "@/lib/dlp/service";

export const dynamic = "force-dynamic";

export const PATCH = route(
  { area: "dlp", bodySchema: dlpIncidentStatusUpdateSchema, section: "dlp" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const updated = await updateIncidentStatus(auth.tenantId, id, body.status);
    return {
      data: updated,
      audit: {
        action: "dlp.incident.status",
        objectType: "dlp_incident",
        objectId: id,
        after: { status: body.status },
      },
    };
  },
);
