/**
 * /api/v1/ztna/evaluate — the user-to-resource access enforcement point
 * (spec §4.4). POST {subject{user, groups, deviceId}, appId} loads the app's
 * ENABLED policies, resolves the device's current posture verdict from the
 * latest stored posture check, and returns the decideAccess envelope
 * (decision + matched policy + reason) — this is what the view's "Access
 * Simulator" card calls. Every evaluation is audited so /stats can surface
 * recent denials.
 */

import { route } from "@/lib/api/handler";
import { ztnaEvaluateSchema } from "@/lib/validators/ztna";
import { evaluateAccess } from "@/lib/ztna/service";

export const dynamic = "force-dynamic";

export const POST = route({ area: "ztna", bodySchema: ztnaEvaluateSchema }, async ({ auth, body }) => {
  const result = await evaluateAccess(auth.tenantId, body);
  return {
    data: result,
    audit: {
      action: "ztna.evaluate",
      objectType: "ztna_application",
      objectId: result.appId,
      objectName: result.appName,
      after: {
        decision: result.decision,
        reason: result.reason,
        matchedPolicyId: result.matchedPolicyId,
        postureVerdict: result.postureVerdict,
        user: body.subject.user ?? null,
        deviceId: body.subject.deviceId ?? null,
        appName: result.appName,
      },
    },
  };
});
