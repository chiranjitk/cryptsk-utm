/**
 * POST /api/v1/wan-policies/{id}/probe — force probe now (M02 §4 "Probe now"
 * button). Runs an immediate engine probe cycle and returns the fresh state;
 * disabled policies are rejected (M02 §3 error table). Policies the engine
 * does not know (created after bootstrap) get a one-shot fallback evaluation.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { getEngine } from "@/lib/engine";
import { probeGateway } from "@/lib/host/tools";
import { idParamSchema } from "@/lib/validators/network";
import { shapeWanPolicy } from "@/lib/network/shapes";

export const dynamic = "force-dynamic";

export const POST = route({ area: "network", section: "routing" }, async ({ auth, params }) => {
  const { id } = idParamSchema.parse(params);
  const policy = await db.wanPolicy.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!policy) throw ApiError.notFound(`WAN policy ${id} not found`);
  if (!policy.enabled) throw ApiError.validation("Cannot probe a disabled policy");

  // REAL probe: tracked policies run an immediate engine probe; policies the
  // engine has not picked up yet get a real one-shot gateway probe instead.
  let state = await getEngine().forceProbe(policy.interfaceName);
  if (state === null) {
    state = (await probeGateway(policy.interfaceName)).state;
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
