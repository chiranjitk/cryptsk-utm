/**
 * /api/v1/incidents/[id] — single incident (with append-only timeline),
 * PATCH by body kind (status transition | assignment; each workflow verb
 * appends its own timeline entry), DELETE (resolved incidents only).
 */

import { route, numericId } from "@/lib/api/handler";
import { incidentPatchSchema } from "@/lib/validators/incidents";
import { assign, deleteIncident, getIncident, transition } from "@/lib/incidents/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "ips_events" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  return { data: await getIncident(auth.tenantId, id) };
});

export const PATCH = route(
  { area: "ips_events", bodySchema: incidentPatchSchema },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const actor = auth.username ?? "system";
    if (body.kind === "status") {
      const updated = await transition(auth.tenantId, id, body, actor);
      return {
        data: updated,
        audit: {
          action: "incident.status",
          objectType: "incident",
          objectId: id,
          objectName: updated.ref,
          after: { status: updated.status, resolvedAt: updated.resolvedAt },
        },
      };
    }
    const updated = await assign(auth.tenantId, id, body, actor);
    return {
      data: updated,
      audit: {
        action: "incident.assign",
        objectType: "incident",
        objectId: id,
        objectName: updated.ref,
        after: { assignedTo: updated.assignedTo },
      },
    };
  },
);

export const DELETE = route({ area: "ips_events" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  const deleted = await deleteIncident(auth.tenantId, id);
  return { data: deleted, audit: { action: "incident.delete", objectType: "incident", objectId: id } };
});
