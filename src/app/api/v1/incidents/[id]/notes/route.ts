/**
 * POST /api/v1/incidents/[id]/notes — append an analyst note to the
 * incident timeline (action `note`, actor = authenticated username).
 */

import { route, numericId } from "@/lib/api/handler";
import { incidentNoteSchema } from "@/lib/validators/incidents";
import { addNote } from "@/lib/incidents/service";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "ips_events", bodySchema: incidentNoteSchema },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const updated = await addNote(auth.tenantId, id, body.note, auth.username ?? "system");
    return {
      data: updated,
      audit: { action: "incident.note", objectType: "incident", objectId: id, objectName: updated.ref },
    };
  },
);
