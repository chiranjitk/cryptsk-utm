/**
 * POST /api/v1/casb/scan — shadow-IT scan pass (Phase 4 §4.3): aggregates the
 * nDPI-derived app-control logs inside {windowMinutes} (default 1440 = 24h)
 * into SaasDiscovery rows, classified against the tenant SaaS catalog
 * (auto-seeded with the shipped defaults on first run).
 */

import { route } from "@/lib/api/handler";
import { casbScanSchema } from "@/lib/validators/casb";
import { runScan } from "@/lib/casb/service";

export const dynamic = "force-dynamic";

export const POST = route({ area: "casb", bodySchema: casbScanSchema }, async ({ auth, body }) => {
  const summary = await runScan(auth.tenantId, { windowMinutes: body.windowMinutes });
  return {
    data: summary,
    audit: {
      action: "casb.scan.run",
      objectType: "saas_discovery",
      after: { ...summary, windowMinutes: body.windowMinutes },
    },
  };
});
