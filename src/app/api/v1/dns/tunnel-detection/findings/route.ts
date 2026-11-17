/**
 * GET /api/v1/dns/tunnel-detection/findings — persisted DnsTunnelFinding rows
 * (Phase 3 §3.4). Filters: status, verdict, q (client-IP substring); newest
 * window first, server-paginated envelope.
 */

import { route } from "@/lib/api/handler";
import { tunnelFindingsQuerySchema } from "@/lib/validators/dns-tunnel";
import { listFindings } from "@/lib/dns/tunnel-service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "dns_dhcp", querySchema: tunnelFindingsQuerySchema }, async ({ auth, query }) => {
  return listFindings(auth.tenantId, query);
});
