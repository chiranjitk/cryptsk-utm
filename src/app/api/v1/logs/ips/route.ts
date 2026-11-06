/** GET /api/v1/logs/ips — server-paginated IPS event page (M09 §3). */

import { route } from "@/lib/api/handler";
import { ipsLogQuerySchema } from "@/lib/validators/logs";
import { listIpsEvents } from "@/lib/logs/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "logs", querySchema: ipsLogQuerySchema }, async ({ auth, query }) => {
  const { rows, meta } = await listIpsEvents(auth.tenantId, query);
  return { data: rows, meta };
});
