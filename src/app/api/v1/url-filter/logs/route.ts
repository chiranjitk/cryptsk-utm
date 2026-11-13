/**
 * URL filter logs (M16 §2.3.5) — paged-lite list, newest first.
 * Filters: ?limit=100 (1–100), ?action=allowed|blocked|warned, ?q= free text
 * over url / domain / clientIp.
 */

import { route } from "@/lib/api/handler";
import { urlFilterLogQuerySchema } from "@/lib/validators/url-filter";
import { listLogs } from "@/app/api/v1/url-filter/service";

export const dynamic = "force-dynamic";

export const GET = route(
  { area: "url_filter", querySchema: urlFilterLogQuerySchema },
  async ({ auth, query }) => {
    const { data, meta } = await listLogs(auth.tenantId, query);
    return { data, meta };
  },
);
