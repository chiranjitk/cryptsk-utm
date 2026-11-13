/**
 * Service-layer integrity helpers for M03 (ER_DIAGRAM §3): JSON id arrays are
 * LOGICAL references — every id must exist in the respective object-or-group
 * table (mixed semantics), and referenced objects/groups/zones/schedules must
 * not be deleted while rules still point at them (409 CONFLICT).
 *
 * Enterprise fixes (2026-11-16):
 *  • EVERY scan is tenant-scoped — the hardcoded tenant 1 previously validated
 *    deletions against the wrong tenant's rules.
 *  • serviceObjectReferences walks via-group chains like the address twin —
 *    a service object hidden inside a referenced service group is NOT free.
 *  • zoneReferences also reports NAT rules whose outgoingIface sits inside the
 *    zone (NAT references zones through interface names, not zone ids).
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
async function scanRuleArrays(
  tenantId: number,
  id: number,
  columns: ("addrIds" | "serviceIds" | "zoneIds")[],
): Promise<RefRow[]> {
  const refs: RefRow[] = [];
  const fw = await db.firewallRule.findMany({ where: { tenantId } });
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
  const nat = await db.natRule.findMany({ where: { tenantId } });
  for (const r of nat) {
    const hit = columns.some((c) => {
      const ids = c === "serviceIds" ? parseIds(r.serviceIds) : [...parseIds(r.srcAddrIds), ...parseIds(r.dstAddrIds)];
      return ids.includes(id);
    });
    if (hit) refs.push({ ruleName: r.name ?? `#${r.id}`, ruleType: "nat" });
  }
  return refs;
}

export async function addressObjectReferences(tenantId: number, id: number): Promise<RefRow[]> {
  // referenced directly by rules OR via a group that a rule references
  const direct = await scanRuleArrays(tenantId, id, ["addrIds"]);
  const groups = await db.addressGroup.findMany({ where: { tenantId } });
  const viaGroup = await Promise.all(
    groups
      .filter((g) => parseIds(g.memberIds).includes(id))
      .map(async (g) => {
        const nested = await scanRuleArrays(tenantId, g.id, ["addrIds"]);
        return nested.map((n) => ({ ...n, ruleName: `${n.ruleName} (via group ${g.name})` }));
      }),
  );
  return [...direct, ...viaGroup.flat()];
}

export function addressGroupReferences(tenantId: number, id: number): Promise<RefRow[]> {
  return scanRuleArrays(tenantId, id, ["addrIds"]);
}

export async function serviceObjectReferences(tenantId: number, id: number): Promise<RefRow[]> {
  // referenced directly by rules OR via a group that a rule references —
  // deleting a member out from under a live group leaves a dangling id that
  // is silently skipped at expansion (a rule quietly loses its service scope)
  const direct = await scanRuleArrays(tenantId, id, ["serviceIds"]);
  const groups = await db.serviceGroup.findMany({ where: { tenantId } });
  const viaGroup = await Promise.all(
    groups
      .filter((g) => parseIds(g.memberIds).includes(id))
      .map(async (g) => {
        const nested = await scanRuleArrays(tenantId, g.id, ["serviceIds"]);
        return nested.map((n) => ({ ...n, ruleName: `${n.ruleName} (via group ${g.name})` }));
      }),
  );
  return [...direct, ...viaGroup.flat()];
}

export function serviceGroupReferences(tenantId: number, id: number): Promise<RefRow[]> {
  return scanRuleArrays(tenantId, id, ["serviceIds"]);
}

export async function zoneReferences(tenantId: number, id: number): Promise<RefRow[]> {
  const refs = await scanRuleArrays(tenantId, id, ["zoneIds"]);
  // NAT references zones transitively through interface names
  const zone = await db.zone.findFirst({ where: { id, tenantId } });
  if (zone) {
    const ifaces = safeJsonStrings(zone.interfaceNames);
    const nat = await db.natRule.findMany({
      where: { tenantId, outgoingIface: { in: ifaces } },
      select: { id: true, name: true },
    });
    for (const n of nat) refs.push({ ruleName: `${n.name ?? `#${n.id}`} (via interface)`, ruleType: "nat" });
  }
  return refs;
}

function safeJsonStrings(raw: string): string[] {
  try {
    const v = JSON.parse(raw);
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
  } catch {
    return [];
  }
}

export async function scheduleReferences(tenantId: number, id: number): Promise<RefRow[]> {
  const rules = await db.firewallRule.findMany({ where: { tenantId, scheduleId: id }, select: { name: true } });
  return rules.map((r) => ({ ruleName: r.name, ruleType: "firewall" as const }));
}

export async function ipsPolicyReferences(tenantId: number, id: number): Promise<RefRow[]> {
  const rules = await db.firewallRule.findMany({ where: { tenantId, ipsPolicyId: id }, select: { name: true } });
  return rules.map((r) => ({ ruleName: r.name, ruleType: "firewall" as const }));
}

export async function qosPolicyReferences(tenantId: number, id: number): Promise<RefRow[]> {
  const rules = await db.firewallRule.findMany({ where: { tenantId, qosPolicyId: id }, select: { name: true } });
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

// ── empty-group guard (match-any prevention) ───────────────────────────────

export interface EmptyGroupHit {
  groupId: number;
  groupName: string;
  kind: "address" | "service";
}

/**
 * SECURITY GUARD: referencing an EMPTY group in a rule historically compiled
 * to a clause-less (match-any) nft statement — an accidental allow-all. A
 * rule body may only reference groups with at least one member.
 */
export async function findEmptyGroupReferences(
  tenantId: number,
  body: { srcAddrIds: number[]; dstAddrIds: number[]; serviceIds: number[] },
): Promise<EmptyGroupHit[]> {
  const addrGroupIds = [...new Set([...body.srcAddrIds, ...body.dstAddrIds])];
  const svcGroupIds = [...new Set(body.serviceIds)];
  const hits: EmptyGroupHit[] = [];
  const [addrGroups, svcGroups] = await Promise.all([
    addrGroupIds.length ? db.addressGroup.findMany({ where: { tenantId, id: { in: addrGroupIds } } }) : Promise.resolve([]),
    svcGroupIds.length ? db.serviceGroup.findMany({ where: { tenantId, id: { in: svcGroupIds } } }) : Promise.resolve([]),
  ]);
  for (const g of addrGroups) {
    if (parseIds(g.memberIds).length === 0) hits.push({ groupId: g.id, groupName: g.name, kind: "address" });
  }
  for (const g of svcGroups) {
    if (parseIds(g.memberIds).length === 0) hits.push({ groupId: g.id, groupName: g.name, kind: "service" });
  }
  return hits;
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
