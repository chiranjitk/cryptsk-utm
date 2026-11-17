/**
 * PATCH /api/v1/dns/tunnel-detection/findings/[id]/status — triage workflow
 * (Phase 3 §3.4): open → acknowledged → resolved. Audit dns.tunnel-finding.status.
 */

import { route, numericId } from "@/lib/api/handler";
import { tunnelFindingStatusUpdateSchema } from "@/lib/validators/dns-tunnel";
import { updateFindingStatus } from "@/lib/dns/tunnel-service";

export const dynamic = "force-dynamic";

export const PATCH = route(
  { area: "dns_dhcp", bodySchema: tunnelFindingStatusUpdateSchema },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const updated = await updateFindingStatus(auth.tenantId, id, body.status);
    return {
      data: updated,
      audit: {
        action: "dns.tunnel-finding.status",
        objectType: "dns_tunnel_finding",
        objectId: id,
        after: { status: body.status },
      },
    };
  },
);
