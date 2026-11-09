/**
 * GET  /api/v1/wan-policies — multi-WAN policies with live probe states
 * (M02 §4/#/network/wan): the engine's wanStates map wins over the stored
 * column when it knows the iface. POST — create; iface must exist and must
 * not already carry a policy (one per iface, 409).
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { getEngine } from "@/lib/engine";
import { netListQuery, wanPolicyBodySchema } from "@/lib/validators/network";
import { assertIfacesExist } from "@/lib/network/iface-service";
import { shapeWanPolicy } from "@/lib/network/shapes";

export const dynamic = "force-dynamic";

export const GET = route({ area: "network", querySchema: netListQuery }, async ({ auth }) => {
  const live = new Map(getEngine().wanStates.map((w) => [w.iface, w.state]));
  const rows = await db.wanPolicy.findMany({
    where: { tenantId: auth.tenantId },
    orderBy: [{ priority: "asc" }, { id: "asc" }],
  });
  return { data: rows.map((p) => shapeWanPolicy(p, live.get(p.interfaceName))) };
});

export const POST = route(
  { area: "network", bodySchema: wanPolicyBodySchema, section: "routing" },
  async ({ auth, body }) => {
    await assertIfacesExist(auth.tenantId, [body.interfaceName]);

    const existing = await db.wanPolicy.findFirst({
      where: { tenantId: auth.tenantId, interfaceName: body.interfaceName },
    });
    if (existing) throw ApiError.conflict(`A WAN policy for ${body.interfaceName} already exists`);

    // NOTE: the host collector re-reads WAN policies every probe cycle, so new
    // policies start probing within ~10 s; until then the state stays "unknown".
    const created = await db.wanPolicy.create({
      data: {
        tenantId: auth.tenantId,
        interfaceName: body.interfaceName,
        mode: body.mode,
        weight: body.weight,
        priority: body.priority,
        probeType: body.probeType,
        probeTarget: body.probeTarget,
        intervalSec: body.intervalSec,
        timeoutMs: body.timeoutMs,
        failThreshold: body.failThreshold,
        okThreshold: body.okThreshold,
        state: "unknown",
        enabled: body.enabled,
      },
    });
    return {
      data: shapeWanPolicy(created),
      audit: { action: "wan.create", objectType: "wan_policy", objectId: created.id, objectName: created.interfaceName },
    };
  },
);
