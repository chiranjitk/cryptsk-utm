/**
 * Service-layer integrity helpers for M03 (ER_DIAGRAM §3): JSON id arrays are
 * LOGICAL references — every id must exist in the respective object-or-group
 * table (mixed semantics), and referenced objects/groups/zones/schedules must
 * not be deleted while rules still point at them (409 CONFLICT).
 */

import { db } from "@/lib/db";

export function parseIds(raw: string): number[] {
  try {
    const v = JSON.parse(raw);
    return Array.isArray(v) ? v.filter((x): x is number => typeof x === "number") : [];
  } catch {
    return [];
  }
}

export interface RefRow {
  ruleName: string;
  ruleType: "firewall" | "nat";
}

/** Scan firewall + NAT rules for `id` inside the given JSON column (both directions). */
async function scanRuleArrays(id: number, columns: ("addrIds" | "serviceIds" | "zoneIds")[]): Promise<RefRow[]> {
  const refs: RefRow[] = [];
  const fw = await db.firewallRule.findMany({ where: { tenantId: 1 } });
  for (const r of fw) {
    const hit = columns.some((c) => {
      // NOTE: parse each JSON column SEPARATELY — concatenating two JSON arrays
      // ("[1] [5]") is invalid JSON and silently yields no references.
      const ids =
        c === "addrIds"
          ? [...parseIds(r.srcAddrIds), ...parseIds(r.dstAddrIds)]
          : c === "serviceIds"
            ? parseIds(r.serviceIds)
            : [...parseIds(r.srcZoneIds), ...parseIds(r.dstZoneIds)];
      return ids.includes(id);
    });
    if (hit) refs.push({ ruleName: r.name, ruleType: "firewall" });
  }
  const nat = await db.natRule.findMany({ where: { tenantId: 1 } });
  for (const r of nat) {
    const hit = columns.some((c) => {
      const ids = c === "serviceIds" ? parseIds(r.serviceIds) : [...parseIds(r.srcAddrIds), ...parseIds(r.dstAddrIds)];
      return ids.includes(id);
    });
    if (hit) refs.push({ ruleName: r.name ?? `#${r.id}`, ruleType: "nat" });
  }
  return refs;
}

export async function addressObjectReferences(id: number): Promise<RefRow[]> {
  // referenced directly by rules OR via a group that a rule references
  const direct = await scanRuleArrays(id, ["addrIds"]);
  const groups = await db.addressGroup.findMany({ where: { tenantId: 1 } });
  const viaGroup = await Promise.all(
    groups
      .filter((g) => parseIds(g.memberIds).includes(id))
      .map(async (g) => {
        const nested = await scanRuleArrays(g.id, ["addrIds"]);
        return nested.map((n) => ({ ...n, ruleName: `${n.ruleName} (via group ${g.name})` }));
      }),
  );
  return [...direct, ...viaGroup.flat()];
}

export function addressGroupReferences(id: number): Promise<RefRow[]> {
  return scanRuleArrays(id, ["addrIds"]);
}

export function serviceObjectReferences(id: number): Promise<RefRow[]> {
  return scanRuleArrays(id, ["serviceIds"]);
}

export function serviceGroupReferences(id: number): Promise<RefRow[]> {
  return scanRuleArrays(id, ["serviceIds"]);
}

export function zoneReferences(id: number): Promise<RefRow[]> {
  return scanRuleArrays(id, ["zoneIds"]);
}

export async function scheduleReferences(id: number): Promise<RefRow[]> {
  const rules = await db.firewallRule.findMany({ where: { tenantId: 1, scheduleId: id }, select: { name: true } });
  return rules.map((r) => ({ ruleName: r.name, ruleType: "firewall" as const }));
}

export async function ipsPolicyReferences(id: number): Promise<RefRow[]> {
  const rules = await db.firewallRule.findMany({ where: { tenantId: 1, ipsPolicyId: id }, select: { name: true } });
  return rules.map((r) => ({ ruleName: r.name, ruleType: "firewall" as const }));
}

export async function qosPolicyReferences(id: number): Promise<RefRow[]> {
  const rules = await db.firewallRule.findMany({ where: { tenantId: 1, qosPolicyId: id }, select: { name: true } });
  return rules.map((r) => ({ ruleName: r.name, ruleType: "firewall" as const }));
}

// ── existence validation for mixed id arrays ───────────────────────────────

export interface IdExistence {
  ok: boolean;
  offending: number[];
}

/** Validate ids against a set of known ids (mixed object+group semantics). */
export function checkIds(ids: number[], known: Set<number>): IdExistence {
  const offending = ids.filter((id) => !known.has(id));
  return { ok: offending.length === 0, offending: [...new Set(offending)] };
}

export async function loadAddressIdSet(tenantId: number): Promise<Set<number>> {
  const [objs, groups] = await Promise.all([
    db.addressObject.findMany({ where: { tenantId }, select: { id: true } }),
    db.addressGroup.findMany({ where: { tenantId }, select: { id: true } }),
  ]);
  return new Set([...objs.map((o) => o.id), ...groups.map((g) => g.id)]);
}

export async function loadServiceIdSet(tenantId: number): Promise<Set<number>> {
  const [objs, groups] = await Promise.all([
    db.serviceObject.findMany({ where: { tenantId }, select: { id: true } }),
    db.serviceGroup.findMany({ where: { tenantId }, select: { id: true } }),
  ]);
  return new Set([...objs.map((o) => o.id), ...groups.map((g) => g.id)]);
}

export async function loadZoneIdSet(tenantId: number): Promise<Set<number>> {
  const zones = await db.zone.findMany({ where: { tenantId }, select: { id: true } });
  return new Set(zones.map((z) => z.id));
}

export async function loadUserIdSet(tenantId: number): Promise<Set<number>> {
  const users = await db.user.findMany({ where: { tenantId }, select: { id: true } });
  return new Set(users.map((u) => u.id));
}

export async function assertNewIdsValid(tenantId: number, body: {
  srcZoneIds: number[];
  dstZoneIds: number[];
  srcAddrIds: number[];
  dstAddrIds: number[];
  serviceIds: number[];
  userIds: number[];
  scheduleId?: number | null;
  ipsPolicyId?: number | null;
  qosPolicyId?: number | null;
}): Promise<{ ok: true } | { ok: false; message: string; details: unknown }> {
  const [zones, addrs, services, users] = await Promise.all([
    loadZoneIdSet(tenantId),
    loadAddressIdSet(tenantId),
    loadServiceIdSet(tenantId),
    loadUserIdSet(tenantId),
  ]);

  const zoneCheck = checkIds([...body.srcZoneIds, ...body.dstZoneIds], zones);
  if (!zoneCheck.ok)
    return { ok: false, message: "Unknown zone id in srcZoneIds/dstZoneIds", details: { offendingIds: zoneCheck.offending } };

  const addrCheck = checkIds([...body.srcAddrIds, ...body.dstAddrIds], addrs);
  if (!addrCheck.ok)
    return { ok: false, message: "Unknown address object/group id in srcAddrIds/dstAddrIds", details: { offendingIds: addrCheck.offending } };

  const svcCheck = checkIds(body.serviceIds, services);
  if (!svcCheck.ok)
    return { ok: false, message: "Unknown service object/group id in serviceIds", details: { offendingIds: svcCheck.offending } };

  const userCheck = checkIds(body.userIds, users);
  if (!userCheck.ok)
    return { ok: false, message: "Unknown user id in userIds", details: { offendingIds: userCheck.offending } };

  if (body.scheduleId != null) {
    const s = await db.scheduleObject.findFirst({ where: { tenantId, id: body.scheduleId } });
    if (!s) return { ok: false, message: "Unknown scheduleId", details: { offendingIds: [body.scheduleId] } };
  }
  if (body.ipsPolicyId != null) {
    const p = await db.ipsPolicy.findFirst({ where: { tenantId, id: body.ipsPolicyId } });
    if (!p) return { ok: false, message: "Unknown ipsPolicyId", details: { offendingIds: [body.ipsPolicyId] } };
  }
  if (body.qosPolicyId != null) {
    const q = await db.qosPolicy.findFirst({ where: { tenantId, id: body.qosPolicyId } });
    if (!q) return { ok: false, message: "Unknown qosPolicyId", details: { offendingIds: [body.qosPolicyId] } };
  }
  return { ok: true };
}
