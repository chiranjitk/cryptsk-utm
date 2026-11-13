/**
 * PUT/DELETE /api/v1/pbr-rules/{id} — replace / delete a PBR rule
 * (PUT re-validates object/group refs + outgoingIface; 404s on missing.
 * Position moves go through /move — PUT keeps the row in place.)
 * DELETE withdraws the rule's kernel policy entries (best effort, gated).
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { idParamSchema, pbrBodySchema, type PbrBody } from "@/lib/validators/network";
import { assertIfacesExist } from "@/lib/network/iface-service";
import { shapePbrRule } from "@/lib/network/shapes";
import { loadAddressIdSet, loadServiceIdSet } from "@/lib/firewall/refs";
import { buildPbrTeardownPlan, resolvePbrCidrs, type PbrRuleView } from "@/lib/network/pbr-os";
import { convergeRouteSafe } from "@/lib/network/route-apply";

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

export const PUT = route(
  { area: "network", bodySchema: pbrBodySchema, section: "routing" },
  async ({ auth, params, body }) => {
    const { id } = idParamSchema.parse(params);
    const before = await db.pbrRule.findFirst({ where: { id, tenantId: auth.tenantId } });
    if (!before) throw ApiError.notFound(`PBR rule ${id} not found`);
    await assertPbrRefs(auth.tenantId, body);

    // PUT keeps the row in place — explicit moves go through position on create
    const updated = await db.pbrRule.update({
      where: { id },
      data: {
        name: body.name,
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
      data: shapePbrRule(updated),
      audit: {
        action: "pbr.update",
        objectType: "pbr_rule",
        objectId: id,
        objectName: before.name,
        before: shapePbrRule(before),
        after: shapePbrRule(updated),
      },
    };
  },
);

export const DELETE = route({ area: "network", section: "routing" }, async ({ auth, params }) => {
  const { id } = idParamSchema.parse(params);
  const row = await db.pbrRule.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!row) throw ApiError.notFound(`PBR rule ${id} not found`);

  // withdraw kernel policy entries first (gated; DB delete never rolls back)
  const view: PbrRuleView = {
    id: row.id,
    name: row.name,
    position: row.position,
    enabled: row.enabled,
    srcAddrIds: JSON.parse(row.srcAddrIds || "[]"),
    dstAddrIds: JSON.parse(row.dstAddrIds || "[]"),
    serviceIds: JSON.parse(row.serviceIds || "[]"),
    outgoingIface: row.outgoingIface,
    gateway: row.gateway,
  };
  const [src, dst] = await Promise.all([
    resolvePbrCidrs(auth.tenantId, view.srcAddrIds).catch(() => []),
    resolvePbrCidrs(auth.tenantId, view.dstAddrIds).catch(() => []),
  ]);
  const teardown = buildPbrTeardownPlan(view, src.filter((s) => s.cidr).length, dst.filter((d) => d.cidr).length);
  const os = await convergeRouteSafe(async () => ({ name: teardown.name, osName: null, steps: teardown.steps }));

  await db.pbrRule.delete({ where: { id } });
  return {
    data: { ok: true },
    os,
    audit: {
      action: "pbr.delete",
      objectType: "pbr_rule",
      objectId: row.id,
      objectName: row.name,
      before: shapePbrRule(row),
    },
  };
});
