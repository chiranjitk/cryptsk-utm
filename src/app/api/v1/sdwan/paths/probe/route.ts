/**
 * Simulated probe cycle (M20 §2.5) — POST /paths/probe walks every path of
 * enabled sites in enabled overlays (optionally scoped by `overlayId`) with a
 * deterministic ±15% pseudo-random walk, re-evaluates up/degraded/down against
 * the overlay's first attached SLA profile (fallback 150/30/1.0), updates the
 * rows and returns the summary. Audit `sdwan.probe`.
 */

import { route } from "@/lib/api/handler";
import { probeBodySchema } from "@/lib/validators/sdwan";
import { probePaths } from "@/app/api/v1/sdwan/service";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "sdwan", bodySchema: probeBodySchema, section: "sdwan" },
  async ({ auth, body }) => {
    const summary = await probePaths(auth.tenantId, body);
    return {
      data: summary,
      audit: {
        action: "sdwan.probe",
        objectType: "sdwan_path",
        ...(body.overlayId !== undefined ? { objectId: body.overlayId } : {}),
        objectName: body.overlayId !== undefined ? `overlay ${body.overlayId}` : "all overlays",
        after: summary,
      },
    };
  },
);
