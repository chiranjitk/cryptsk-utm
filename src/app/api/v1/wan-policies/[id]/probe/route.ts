/**
 * POST /api/v1/wan-policies/{id}/probe — force probe now (M02 §4 "Probe now"
 * button). Runs an immediate engine probe cycle and returns the fresh state;
 * disabled policies are rejected (M02 §3 error table). Policies the engine
 * does not know (created after bootstrap) get a one-shot fallback evaluation.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { getMockEngine } from "@/lib/engine/mock-engine";
import { idParamSchema } from "@/lib/validators/network";
import { shapeWanPolicy } from "@/lib/network/shapes";

export const dynamic = "force-dynamic";

export const POST = route({ area: "network", section: "routing" }, async ({ auth, params }) => {
  const { id } = idParamSchema.parse(params);
  const policy = await db.wanPolicy.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!policy) throw ApiError.notFound(`WAN policy ${id} not found`);
  if (!policy.enabled) throw ApiError.validation("Cannot probe a disabled policy");

  let state = getMockEngine().forceProbe(policy.interfaceName);
  if (state === null) {
    // engine probe map only covers boot-time policies — one-shot fallback
    state = Math.random() < 0.85 ? "up" : "degraded";
  }

  const updated = await db.wanPolicy.update({ where: { id: policy.id }, data: { state } });
  return {
    data: shapeWanPolicy(updated),
    audit: {
      action: "wan.probe",
      objectType: "wan_policy",
      objectId: policy.id,
      objectName: policy.interfaceName,
    },
  };
});
