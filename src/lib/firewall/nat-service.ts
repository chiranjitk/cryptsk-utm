/**
 * NAT rule service — create/update/reorder + the 1:1 (static NAT) helper
 * (M03 §4: paired dnat + snat rows in ONE transaction + one audit entry,
 * linked via a shared `1:1:<uuid>` comment marker).
 */

import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { renumberNatRules } from "./positions";

export type NatRuleBody = {
  name?: string | null;
  enabled: boolean;
  position?: number;
  type: string;
  srcAddrIds: number[];
  dstAddrIds: number[];
  serviceIds: number[];
  outgoingIface?: string | null;
  translatedSrc?: string | null;
  translatedSrcPool: string[];
  overload: boolean;
  translatedDst?: string | null;
  translatedPort?: number | null;
  translatedPortRange?: string | null;
  logging: string;
  comment?: string | null;
};

function natData(tenantId: number, position: number, body: NatRuleBody) {
  return {
    tenantId,
    name: body.name ?? null,
    position,
    type: body.type,
    enabled: body.enabled,
    srcAddrIds: JSON.stringify(body.srcAddrIds),
    dstAddrIds: JSON.stringify(body.dstAddrIds),
    serviceIds: JSON.stringify(body.serviceIds),
    outgoingIface: body.outgoingIface ?? null,
    translatedSrc: body.translatedSrc ?? null,
    translatedSrcPool: JSON.stringify(body.translatedSrcPool),
    overload: body.overload,
    translatedDst: body.translatedDst ?? null,
    translatedPort: body.translatedPort ?? null,
    translatedPortRange: body.translatedPortRange ?? null,
    logging: body.logging,
    comment: body.comment ?? null,
  };
}

export async function createNatRule(
  tenantId: number,
  body: NatRuleBody,
): Promise<{ id: number; name: string | null; position: number }> {
  const max = await db.natRule.aggregate({ where: { tenantId }, _max: { position: true } });
  const appendPos = (max._max.position ?? 0) + 1;
  const desired = body.position ? Math.min(body.position, appendPos) : appendPos;
  const created = await db.$transaction(async (tx) => {
    if (desired < appendPos) {
      await tx.natRule.updateMany({ where: { tenantId, position: { gte: desired } }, data: { position: { increment: 1 } } });
    }
    return tx.natRule.create({ data: natData(tenantId, desired, body), select: { id: true, name: true, position: true } });
  });
  return created;
}

export async function updateNatRule(tenantId: number, id: number, body: NatRuleBody): Promise<{ id: number }> {
  const existing = await db.natRule.findFirst({ where: { id, tenantId } });
  if (!existing) throw ApiError.notFound(`NAT rule ${id} not found`);
  await db.natRule.update({ where: { id: existing.id }, data: natData(tenantId, existing.position, body) });
  return { id: existing.id };
}

export async function reorderNatRules(tenantId: number, orderedIds: number[]): Promise<void> {
  const all = await db.natRule.findMany({ where: { tenantId }, select: { id: true } });
  const known = new Set(all.map((r) => r.id));
  const seen = new Set<number>();
  for (const id of orderedIds) {
    if (!known.has(id)) throw ApiError.validation(`orderedIds contains unknown NAT rule id ${id}`, { offendingIds: [id] });
    if (seen.has(id)) throw ApiError.validation(`orderedIds contains duplicate id ${id}`, { duplicateIds: [id] });
    seen.add(id);
  }
  const missing = all.filter((r) => !seen.has(r.id)).map((r) => r.id);
  if (missing.length) {
    throw ApiError.validation("orderedIds must be a permutation of all tenant NAT rule ids", { missingIds: missing });
  }
  await db.$transaction(async (tx) => {
    await renumberNatRules(tx as unknown as Parameters<typeof renumberNatRules>[0], tenantId, orderedIds);
  });
}

/** Find-or-create an /32 address object for a raw helper IP. */
async function ensureAddressObject(tenantId: number, ip: string, prefix: string): Promise<number> {
  const name = `${prefix}_${ip.replace(/\./g, "_")}`;
  const existing = await db.addressObject.findFirst({ where: { tenantId, name } });
  if (existing) return existing.id;
  const created = await db.addressObject.create({
    data: { tenantId, name, type: "ip", value: ip, description: "Created by the 1:1 NAT helper" },
  });
  return created.id;
}

export async function createOneToOnePair(
  tenantId: number,
  input: { publicIp: string; internalHost: string; iface?: string; name?: string; comment?: string },
): Promise<{ dnatId: number; snatId: number; marker: string }> {
  const marker = `1:1:${crypto.randomUUID()}`;
  const base = input.name?.trim() || `1to1-${input.publicIp}`;

  const created = await db.$transaction(async (tx) => {
    const max = await tx.natRule.aggregate({ where: { tenantId }, _max: { position: true } });
    let pos = (max._max.position ?? 0) + 1;

    const pubId = await ensureAddressObject(tenantId, input.publicIp, "PUB");
    const hostId = await ensureAddressObject(tenantId, input.internalHost, "HOST");

    const dnat = await tx.natRule.create({
      data: {
        tenantId,
        name: `${base}-dnat`,
        position: pos++,
        type: "dnat",
        enabled: true,
        srcAddrIds: "[]",
        dstAddrIds: JSON.stringify([pubId]),
        serviceIds: "[]",
        outgoingIface: input.iface ?? null,
        translatedSrc: null,
        translatedSrcPool: "[]",
        overload: true,
        translatedDst: input.internalHost,
        translatedPort: null,
        translatedPortRange: null,
        logging: "none",
        comment: input.comment ? `${marker} ${input.comment}` : marker,
      },
      select: { id: true },
    });
    const snat = await tx.natRule.create({
      data: {
        tenantId,
        name: `${base}-snat`,
        position: pos++,
        type: "snat",
        enabled: true,
        srcAddrIds: JSON.stringify([hostId]),
        dstAddrIds: "[]",
        serviceIds: "[]",
        outgoingIface: input.iface ?? null,
        translatedSrc: input.publicIp,
        translatedSrcPool: "[]",
        overload: false,
        translatedDst: null,
        translatedPort: null,
        translatedPortRange: null,
        logging: "none",
        comment: input.comment ? `${marker} ${input.comment}` : marker,
      },
      select: { id: true },
    });
    return { dnatId: dnat.id, snatId: snat.id, marker };
  });
  return created;
}
