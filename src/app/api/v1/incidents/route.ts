/**
 * /api/v1/incidents — incident list + creation (Phase 3 §3.5).
 * POST accepts BOTH shapes: the fromAlert body (sourceRef present → dedupe
 * against open incidents, returns {incident, deduped}) and the manual shape
 * (no sourceRef → plain create). RBAC mirrors /api/v1/ips/events — SOC
 * workflow lives in the ips_events capability area (soc_analysts may act).
 */

import { route } from "@/lib/api/handler";
import { incidentCreateSchema, incidentQuerySchema } from "@/lib/validators/incidents";
import { createIncident, fromAlert, listIncidents } from "@/lib/incidents/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "ips_events", querySchema: incidentQuerySchema }, async ({ auth, query }) => {
  return listIncidents(auth.tenantId, query);
});

export const POST = route(
  { area: "ips_events", bodySchema: incidentCreateSchema },
  async ({ auth, body }) => {
    const actor = auth.username ?? "system";
    if (body.sourceRef) {
      const created = await fromAlert(
        auth.tenantId,
        {
          source: body.source,
          sourceRef: body.sourceRef,
          title: body.title,
          severity: body.severity,
          detail: body.detail ?? {},
        },
        actor,
      );
      return {
        data: created,
        audit: {
          action: "incident.create",
          objectType: "incident",
          objectId: created.incident.id,
          objectName: created.incident.ref,
          after: created.incident,
        },
      };
    }
    const created = await createIncident(auth.tenantId, body, actor);
    return {
      data: { incident: created, deduped: false },
      audit: {
        action: "incident.create",
        objectType: "incident",
        objectId: created.id,
        objectName: created.ref,
        after: created,
      },
    };
  },
);
