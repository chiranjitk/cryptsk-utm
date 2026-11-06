/**
 * POST /api/v1/ips/events/[id]/suppress — `{duration: 24h|7d|forever}` (M04 §3).
 * `forever` → suppressedUntil null + action=suppressed (ENDPOINTS §3 convention).
 */

import { route } from "@/lib/api/handler";
import { ipsSuppressBodySchema } from "@/lib/validators/ips";
import { suppressEvent } from "@/lib/ips/service";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "ips_events", bodySchema: ipsSuppressBodySchema, section: "ips" },
  async ({ auth, body, params }) => {
    const updated = await suppressEvent(auth.tenantId, Number(params.id), body.duration);
    return {
      data: updated,
      audit: {
        action: "ips_event.suppress",
        objectType: "ips_event",
        objectId: updated.id,
        objectName: updated.sid ?? undefined,
        after: { duration: body.duration },
      },
    };
  },
);
