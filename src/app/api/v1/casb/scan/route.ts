/**
 * POST /api/v1/casb/scan — shadow-IT scan pass (Phase 4 §4.3): aggregates the
 * app-control logs newer than the per-tenant scan watermark inside
 * {windowMinutes} (default 1440 = 24h) into SaasDiscovery rows, classified
 * against the tenant SaaS catalog (auto-seeded with the shipped defaults on
 * first run). {reset: true} re-aggregates the whole window (audit fix F-d:
 * clears the watermark for that run) — use to rebuild after catalog edits.
 */

import { route } from "@/lib/api/handler";
import { casbScanSchema } from "@/lib/validators/casb";
import { runScan } from "@/lib/casb/service";

export const dynamic = "force-dynamic";

export const POST = route({ area: "casb", bodySchema: casbScanSchema }, async ({ auth, body }) => {
  const summary = await runScan(auth.tenantId, { windowMinutes: body.windowMinutes, reset: body.reset });
  return {
    data: summary,
    audit: {
      action: "casb.scan.run",
      objectType: "saas_discovery",
      after: { ...summary, windowMinutes: body.windowMinutes, reset: body.reset },
    },
  };
});
