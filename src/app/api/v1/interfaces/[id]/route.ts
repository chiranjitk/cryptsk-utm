/**
 * GET/PUT/DELETE /api/v1/interfaces/{id} — detail, update, delete.
 * Delete cascades per M02 §2: WAN policy → zone interfaceNames refs →
 * StaticRoute soft refs (nulled) → the row itself, all in one transaction.
 *
 * pppoe.password is write-only: shaped payloads carry the mask literal and
 * the audit before/after snapshots omit the key entirely (it is revealed
 * only via POST /pppoe-reveal, audited with sourceIp).
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { idParamSchema, ifaceUpdateSchema } from "@/lib/validators/network";
import { deleteIface, loadShapedIfaces, updateIface, type ShapedIface } from "@/lib/network/iface-service";

export const dynamic = "force-dynamic";

/** Deep-copy a shaped iface for the audit trail with config.pppoe.password removed. */
function auditIface(shaped: ShapedIface | null): ShapedIface | null {
  if (!shaped) return null;
  const cfg = { ...shaped.config };
  const pppoe = cfg.pppoe;
  if (pppoe && typeof pppoe === "object" && !Array.isArray(pppoe)) {
    const { password: _password, ...restPppoe } = pppoe as Record<string, unknown>;
    cfg.pppoe = restPppoe;
  }
  return { ...shaped, config: cfg };
}

export const GET = route({ area: "network" }, async ({ auth, params }) => {
  const { id } = idParamSchema.parse(params);
  const shaped = (await loadShapedIfaces(auth.tenantId)).find((i) => i.id === id);
  if (!shaped) throw ApiError.notFound(`Interface ${id} not found`);
  return { data: shaped };
});

export const PUT = route(
  { area: "network", bodySchema: ifaceUpdateSchema, section: "interfaces" },
  async ({ auth, params, body }) => {
    const { id } = idParamSchema.parse(params);
    const raw = await db.networkInterface.findFirst({ where: { id, tenantId: auth.tenantId } });
    if (!raw) throw ApiError.notFound(`Interface ${id} not found`);
    const before = (await loadShapedIfaces(auth.tenantId)).find((i) => i.id === id) ?? null;

    const updated = await updateIface(auth.tenantId, id, body, raw);
    const after = (await loadShapedIfaces(auth.tenantId)).find((i) => i.id === id) ?? null;

    return {
      data: after,
      os: updated.os,
      audit: {
        action: "iface.update",
        objectType: "interface",
        objectId: id,
        objectName: raw.name,
        before: auditIface(before),
        after: auditIface(after),
      },
    };
  },
);

export const DELETE = route({ area: "network", section: "interfaces" }, async ({ auth, params }) => {
  const { id } = idParamSchema.parse(params);
  const raw = await db.networkInterface.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!raw) throw ApiError.notFound(`Interface ${id} not found`);

  const deleted = await deleteIface(auth.tenantId, raw);
  return {
    data: { ok: true },
    os: deleted.os,
    audit: {
      action: "iface.delete",
      objectType: "interface",
      objectId: deleted.id,
      objectName: deleted.name,
    },
  };
});
