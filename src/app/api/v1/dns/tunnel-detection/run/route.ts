/**
 * POST /api/v1/dns/tunnel-detection/run — Phase 3 §3.4 rule-based DNS
 * tunneling detection pass over the query-log ring (entropy + volume/
 * frequency thresholds; AI DGA classification deferred per spec). Body:
 * {windowMinutes?, stepMinutes?, lookbackMinutes?} — defaults 15/5/60.
 */

import { route } from "@/lib/api/handler";
import { tunnelRunSchema } from "@/lib/validators/dns-tunnel";
import { runDetection } from "@/lib/dns/tunnel-service";

export const dynamic = "force-dynamic";

export const POST = route({ area: "dns_dhcp", bodySchema: tunnelRunSchema }, async ({ auth, body }) => {
  const result = await runDetection({
    tenantId: auth.tenantId,
    windowMinutes: body.windowMinutes,
    stepMinutes: body.stepMinutes,
    lookbackMinutes: body.lookbackMinutes,
  });
  return {
    data: result,
    audit: {
      action: "dns.tunnel-detection.run",
      objectType: "dns_tunnel_finding",
      after: {
        findings: result.findings,
        created: result.created,
        updated: result.updated,
        windowMinutes: body.windowMinutes,
        lookbackMinutes: body.lookbackMinutes,
        ...(result.reason ? { reason: result.reason } : {}),
      },
    },
  };
});
