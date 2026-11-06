/** GET /api/v1/notifications — list (?unread=&type=&page=) (M10 §3). */

import { route } from "@/lib/api/handler";
import { notificationListQuery } from "@/lib/validators/system";
import { listNotifications } from "@/lib/notifications/service";

export const dynamic = "force-dynamic";

export const GET = route(
  { area: "notifications", querySchema: notificationListQuery },
  async ({ auth, query }) => {
    const { data, meta } = await listNotifications(auth.tenantId, query);
    return { data, meta };
  },
);
