/**
 * /api/v1/vpn/sessions — live session list (M05 §3). Filters ?vpnId= (field
 * filter per PROJECT_MEMORY §7.1), ?status=, ?q= + pagination.
 */

import { route } from "@/lib/api/handler";
import { vpnSessionsQuerySchema } from "@/lib/validators/vpn";
import { listSessions } from "@/lib/vpn/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "vpn_sessions", querySchema: vpnSessionsQuerySchema }, async ({ auth, query }) => {
  return listSessions(auth.tenantId, query);
});
