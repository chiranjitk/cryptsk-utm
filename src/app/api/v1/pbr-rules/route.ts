/**
 * GET  /api/v1/pbr-rules — policy-based routing rules, ordered by position
 * (M02 §4 tab 2). POST /api/v1/pbr-rules — create; every address/service id
 * must exist in the mixed object∪group sets, outgoingIface must resolve,
 * position defaults to max+1 (M03-style mixed-ref semantics).
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { netListQuery, pbrBodySchema, type PbrBody } from "@/lib/validators/network";
import { assertIfacesExist } from "@/lib/network/iface-service";
import { shapePbrRule } from "@/lib/network/shapes";
import { loadAddressIdSet, loadServiceIdSet } from "@/lib/firewall/refs";
import { pbrKernelState, readKernelPbrRules } from "@/lib/network/pbr-os";

export const dynamic = "force-dynamic";

/** Mixed object∪group id validation (M02 §3) — same semantics as firewall refs. */
async function assertPbrRefs(tenantId: number, body: PbrBody): Promise<void> {
  const [addrIds, svcIds] = await Promise.all([loadAddressIdSet(tenantId), loadServiceIdSet(tenantId)]);
  for (const id of [...body.srcAddrIds, ...body.dstAddrIds]) {
    if (!addrIds.has(id)) throw ApiError.validation(`Unknown address id ${id}`);
  }
  for (const id of body.serviceIds) {
    if (!svcIds.has(id)) throw ApiError.validation(`Unknown service id ${id}`);
  }
  if (body.outgoingIface) await assertIfacesExist(tenantId, [body.outgoingIface]);
}

export const GET = route({ area: "network", querySchema: netListQuery }, async ({ auth }) => {
  const rows = await db.pbrRule.findMany({
    where: { tenantId: auth.tenantId },
    orderBy: { position: "asc" },
  });
  const shaped = rows.map(shapePbrRule);
  // honest kernel state: in-kernel | missing | config-only (svc match) | disabled | null
  const kernel = await readKernelPbrRules().catch(() => null);
  return {
    data: shaped.map((r) => ({
      ...r,
      kernelState: pbrKernelState(
        {
          id: r.id,
          name: r.name,
          position: r.position,
          enabled: r.enabled,
          srcAddrIds: r.srcAddrIds,
          dstAddrIds: r.dstAddrIds,
          serviceIds: r.serviceIds,
          outgoingIface: r.outgoingIface,
          gateway: r.gateway,
        },
        kernel,
      ),
    })),
  };
});

export const POST = route(
  { area: "network", bodySchema: pbrBodySchema, section: "routing" },
  async ({ auth, body }) => {
    await assertPbrRefs(auth.tenantId, body);

    // position appends at max+1 unless an explicit slot is provided (M03 pattern)
    const max = await db.pbrRule.aggregate({ where: { tenantId: auth.tenantId }, _max: { position: true } });
    const position = body.position ?? (max._max.position ?? 0) + 1;

    const created = await db.pbrRule.create({
      data: {
        tenantId: auth.tenantId,
        name: body.name,
        position,
        enabled: body.enabled,
        srcAddrIds: JSON.stringify(body.srcAddrIds),
        dstAddrIds: JSON.stringify(body.dstAddrIds),
        serviceIds: JSON.stringify(body.serviceIds),
        outgoingIface: body.outgoingIface ?? null,
        gateway: body.gateway ?? null,
        description: body.description ?? null,
      },
    });
    return {
      data: shapePbrRule(created),
      audit: { action: "pbr.create", objectType: "pbr_rule", objectId: created.id, objectName: created.name },
    };
  },
);
