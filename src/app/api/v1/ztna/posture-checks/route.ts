/**
 * /api/v1/ztna/posture-checks — continuous validation snapshots.
 *
 * GET: latest check per device, server-paged (`?deviceId=` scopes to one
 * device). The read first advances continuous validation for the tenant
 * (runContinuousValidation — due rows are re-evaluated; see service docs for
 * the out-of-scope probe transport), so a stale compliance picture is
 * refreshed on every console load.
 *
 * POST: record one manual/agent posture check {deviceId, profileId, results}
 * — runs through the PURE engine and persists verdict + next horizon.
 */

import { route } from "@/lib/api/handler";
import { postureCheckCreateSchema, postureCheckQuerySchema } from "@/lib/validators/ztna";
import { listLatestPostureChecks, recordPostureCheck, runContinuousValidation } from "@/lib/ztna/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "ztna", querySchema: postureCheckQuerySchema }, async ({ auth, query }) => {
  await runContinuousValidation(auth.tenantId);
  const { data, meta } = await listLatestPostureChecks(auth.tenantId, query);
  return { data, meta };
});

export const POST = route({ area: "ztna", bodySchema: postureCheckCreateSchema }, async ({ auth, body }) => {
  const created = await recordPostureCheck(auth.tenantId, body);
  return {
    data: created,
    audit: {
      action: "ztna.posture-check.record",
      objectType: "device_posture_check",
      objectId: created.id,
      objectName: created.deviceId,
      after: { deviceId: created.deviceId, profileId: created.profileId, verdict: created.verdict },
    },
  };
});
