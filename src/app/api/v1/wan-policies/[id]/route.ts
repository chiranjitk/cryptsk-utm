/**
 * PUT/DELETE /api/v1/wan-policies/{id} — edit / remove a multi-WAN policy.
 * PUT validates the interfaceName logical ref on change and keeps the
 * one-policy-per-iface rule (409 on clash). Enterprise additions (G3/G4):
 * the wan-role check applies on re-targeting, and disabling / redefining
 * the probe honestly resets the stored state to "unknown" — a stale
 * "up"/"down" badge from the old probe definition must not survive.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { getEngine } from "@/lib/engine";
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
      const ni = await db.networkInterface.findFirst({
        where: { tenantId: auth.tenantId, name: body.interfaceName },
      });
      if (ni && ni.role !== "wan") {
        throw ApiError.validation(
          `${body.interfaceName} has role "${ni.role}" — WAN policies target interfaces with the "wan" role (assign it in the Interfaces tab first)`,
        );
      }
      const clash = await db.wanPolicy.findFirst({
        where: { tenantId: auth.tenantId, interfaceName: body.interfaceName, id: { not: id } },
      });
      if (clash) throw ApiError.conflict(`A WAN policy for ${body.interfaceName} already exists`);
    }

    // honesty reset (G4): disabling, re-enabling or redefining the probe
    // invalidates the previously measured state
    const redefined =
      body.enabled !== before.enabled ||
      body.probeType !== before.probeType ||
      body.probeTarget !== before.probeTarget;
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
        description: body.description ?? null,
        ...(redefined ? { state: "unknown" } : {}),
      },
    });
    // kernel policy routing follows the edited policy (G2 — no-op when gate off)
    getEngine().wanOsReconverge?.();
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
  // withdraw any kernel policy routing this policy owned (G2 — no-op when gate off)
  getEngine().wanOsReconverge?.();
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
