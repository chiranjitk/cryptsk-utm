/** POST /api/v1/notifications/read-all — mark all read (audited, M10 §3). */

import { route } from "@/lib/api/handler";
import { z } from "@/lib/api/handler";
import { markAllRead } from "@/lib/notifications/service";

export const dynamic = "force-dynamic";

const emptyBody = z.object({}).strict();

export const POST = route({ area: "notifications", bodySchema: emptyBody }, async ({ auth }) => {
  const count = await markAllRead(auth.tenantId);
  return {
    data: { ok: true, marked: count },
    audit: {
      action: "notification.read_all",
      objectType: "notification",
      after: { marked: count },
    },
  };
});
