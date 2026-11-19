/**
 * POST /api/v1/ztna/posture-checks/validate — run the continuous-validation
 * sweep ON DEMAND (audit fix F-d). GET /posture-checks no longer mutates
 * (reads are side-effect free), so the console and schedulers call this
 * audited endpoint to advance due re-checks: stale latest rows
 * (nextCheckAt elapsed) re-evaluate their stored results and persist fresh
 * snapshots. See lib/ztna/service.ts for the out-of-scope probe transport.
 */

import { route } from "@/lib/api/handler";
import { runContinuousValidation } from "@/lib/ztna/service";

export const dynamic = "force-dynamic";

export const POST = route({ area: "ztna" }, async ({ auth }) => {
  const result = await runContinuousValidation(auth.tenantId);
  return {
    data: result,
    audit: {
      action: "ztna.posture-check.validate",
      objectType: "device_posture_check",
      after: { rechecked: result.rechecked, changed: result.changed },
    },
  };
});
