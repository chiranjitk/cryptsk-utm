/** GET /api/v1/logs/firewall — server-paginated flow log page (M09 §3). */

import { route } from "@/lib/api/handler";
import { firewallLogQuerySchema } from "@/lib/validators/logs";
import { listFirewallLogs } from "@/lib/logs/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "logs", querySchema: firewallLogQuerySchema }, async ({ auth, query }) => {
  const { rows, meta } = await listFirewallLogs(auth.tenantId, query);
  return { data: rows, meta };
});
