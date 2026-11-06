/**
 * PUT/DELETE /api/v1/wan-policies/{id} — edit / remove a multi-WAN policy.
 * PUT validates the interfaceName logical ref on change and keeps the
 * one-policy-per-iface rule (409 on clash).
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { idParamSchema, wanPolicyBodySchema } from "@/lib/validators/network";
import { assertIfacesExist } from "@/lib/network/iface-service";
import { shapeWanPolicy } from "@/lib/network/shapes";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "network", bodySchema: wanPolicyBodySchema, section: "routing" },
  async ({ auth, params, body }) => {
    const { id } = idParamSchema.parse(params);
    const before = await db.wanPolicy.findFirst({ where: { id, tenantId: auth.tenantId } });
    if (!before) throw ApiError.notFound(`WAN policy ${id} not found`);

    if (body.interfaceName !== before.interfaceName) {
      await assertIfacesExist(auth.tenantId, [body.interfaceName]);
      const clash = await db.wanPolicy.findFirst({
        where: { tenantId: auth.tenantId, interfaceName: body.interfaceName, id: { not: id } },
      });
      if (clash) throw ApiError.conflict(`A WAN policy for ${body.interfaceName} already exists`);
    }

    const updated = await db.wanPolicy.update({
      where: { id },
      data: {
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
        enabled: body.enabled,
      },
    });
    return {
      data: shapeWanPolicy(updated),
      audit: {
        action: "wan.update",
        objectType: "wan_policy",
        objectId: id,
        objectName: before.interfaceName,
        before: shapeWanPolicy(before),
        after: shapeWanPolicy(updated),
      },
    };
  },
);

export const DELETE = route({ area: "network", section: "routing" }, async ({ auth, params }) => {
  const { id } = idParamSchema.parse(params);
  const row = await db.wanPolicy.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!row) throw ApiError.notFound(`WAN policy ${id} not found`);

  await db.wanPolicy.delete({ where: { id } });
  return {
    data: { ok: true },
    audit: {
      action: "wan.delete",
      objectType: "wan_policy",
      objectId: row.id,
      objectName: row.interfaceName,
      before: shapeWanPolicy(row),
    },
  };
});
