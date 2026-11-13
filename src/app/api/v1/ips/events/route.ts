/**
 * /api/v1/ips/events — filtered, server-paginated event list (M04 §3).
 * Locked param set: severity(csv), sid, q, since, until, category, page, limit.
 * area: ips_events (soc_analysts may read; suppress writes below).
 */

import { route } from "@/lib/api/handler";
import { ipsEventsQuerySchema } from "@/lib/validators/ips";
import { queryEvents } from "@/lib/ips/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "ips_events", querySchema: ipsEventsQuerySchema }, async ({ auth, query }) => {
  return queryEvents(auth.tenantId, query);
});
