/** POST /api/v1/notifications/{id}/read — mark one as read (M10 §3). */

import { route, numericId } from "@/lib/api/handler";
import { notificationReadSchema } from "@/lib/validators/system";
import { ApiError } from "@/lib/api/errors";
import { markRead } from "@/lib/notifications/service";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "notifications", bodySchema: notificationReadSchema },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    if (!Number.isInteger(id)) throw ApiError.notFound("Notification not found");
    const row = await markRead(auth.tenantId, id, body.isRead);
    if (!row) throw ApiError.notFound("Notification not found");
    return {
      data: row,
      audit: {
        action: "notification.read",
        objectType: "notification",
        objectId: row.id,
        after: { isRead: body.isRead },
      },
    };
  },
);
