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
 *  • the rule tables are loaded ONCE per reference scan and via-group chains
 *    expand in memory (the per-group rescan was an N+1 over fw+nat rules).
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

/** One-read rule snapshot — every ref check expands against this in memory. */
interface LoadedRules {
  fw: Array<{
    name: string;
    srcAddrIds: string;
    dstAddrIds: string;
    serviceIds: string;
    srcZoneIds: string;
    dstZoneIds: string;
  }>;
  nat: Array<{ id: number; name: string | null; srcAddrIds: string; dstAddrIds: string; serviceIds: string }>;
}

async function loadRulesOnce(tenantId: number): Promise<LoadedRules> {
  const [fw, nat] = await Promise.all([
    db.firewallRule.findMany({
      where: { tenantId },
      select: { name: true, srcAddrIds: true, dstAddrIds: true, serviceIds: true, srcZoneIds: true, dstZoneIds: true },
    }),
    db.natRule.findMany({
      where: { tenantId },
      select: { id: true, name: true, srcAddrIds: true, dstAddrIds: true, serviceIds: true },
    }),
  ]);
  return { fw, nat };
}

/** Scan a loaded rule snapshot for `id` inside the given JSON columns (both directions). */
function ruleHits(rules: LoadedRules, id: number, columns: ("addrIds" | "serviceIds" | "zoneIds")[]): RefRow[] {
  const refs: RefRow[] = [];
  for (const r of rules.fw) {
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
  for (const r of rules.nat) {
    const hit = columns.some((c) => {
      const ids = c === "serviceIds" ? parseIds(r.serviceIds) : [...parseIds(r.srcAddrIds), ...parseIds(r.dstAddrIds)];
      return ids.includes(id);
    });
    if (hit) refs.push({ ruleName: r.name ?? `#${r.id}`, ruleType: "nat" });
  }
  return refs;
}

/** One fw+nat read; direct hits + via-group hits expand IN MEMORY (no per-group rescan). */
export async function addressObjectReferences(tenantId: number, id: number): Promise<RefRow[]> {
  const rules = await loadRulesOnce(tenantId);
  const direct = ruleHits(rules, id, ["addrIds"]);
  const groups = await db.addressGroup.findMany({ where: { tenantId } });
  const viaGroup = groups
    .filter((g) => parseIds(g.memberIds).includes(id))
    .flatMap((g) =>
      ruleHits(rules, g.id, ["addrIds"]).map((n) => ({ ...n, ruleName: `${n.ruleName} (via group ${g.name})` })),
    );
  return [...direct, ...viaGroup];
}

export function addressGroupReferences(tenantId: number, id: number): Promise<RefRow[]> {
  return scanRuleArrays(tenantId, id, ["addrIds"]);
}

/** One fw+nat read; direct hits + via-group hits expand IN MEMORY (no per-group rescan). */
export async function serviceObjectReferences(tenantId: number, id: number): Promise<RefRow[]> {
  // referenced directly by rules OR via a group that a rule references —
  // deleting a member out from under a live group leaves a dangling id that
  // is silently skipped at expansion (a rule quietly loses its service scope)
  const rules = await loadRulesOnce(tenantId);
  const direct = ruleHits(rules, id, ["serviceIds"]);
  const groups = await db.serviceGroup.findMany({ where: { tenantId } });
  const viaGroup = groups
    .filter((g) => parseIds(g.memberIds).includes(id))
    .flatMap((g) =>
      ruleHits(rules, g.id, ["serviceIds"]).map((n) => ({ ...n, ruleName: `${n.ruleName} (via group ${g.name})` })),
    );
  return [...direct, ...viaGroup];
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

/** Single-scan wrapper for the group-reference / zone-reference helpers. */
async function scanRuleArrays(
  tenantId: number,
  id: number,
  columns: ("addrIds" | "serviceIds" | "zoneIds")[],
): Promise<RefRow[]> {
  return ruleHits(await loadRulesOnce(tenantId), id, columns);
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
  return checkIdsAgainstSets(body, await loadNewIdSets(tenantId));
}

/** Pre-loaded id sets (import path: ONE load for the whole batch). */
export interface NewIdSets {
  zones: Set<number>;
  addrs: Set<number>;
  services: Set<number>;
  users: Set<number>;
  schedules: Set<number>;
  ipsPolicies: Set<number>;
  qosPolicies: Set<number>;
}

export async function loadNewIdSets(tenantId: number): Promise<NewIdSets> {
  const [zones, addrs, services, users, schedules, ipsPolicies, qosPolicies] = await Promise.all([
    loadZoneIdSet(tenantId),
    loadAddressIdSet(tenantId),
    loadServiceIdSet(tenantId),
    loadUserIdSet(tenantId),
    db.scheduleObject.findMany({ where: { tenantId }, select: { id: true } }),
    db.ipsPolicy.findMany({ where: { tenantId }, select: { id: true } }),
    db.qosPolicy.findMany({ where: { tenantId }, select: { id: true } }),
  ]);
  return {
    zones,
    addrs,
    services,
    users,
    schedules: new Set(schedules.map((s) => s.id)),
    ipsPolicies: new Set(ipsPolicies.map((p) => p.id)),
    qosPolicies: new Set(qosPolicies.map((p) => p.id)),
  };
}

/** In-memory id checks against pre-loaded sets — same messages as assertNewIdsValid. */
export function checkIdsAgainstSets(
  body: {
    srcZoneIds: number[];
    dstZoneIds: number[];
    srcAddrIds: number[];
    dstAddrIds: number[];
    serviceIds: number[];
    userIds: number[];
    scheduleId?: number | null;
    ipsPolicyId?: number | null;
    qosPolicyId?: number | null;
  },
  sets: NewIdSets,
): { ok: true } | { ok: false; message: string; details: unknown } {
  const zoneCheck = checkIds([...body.srcZoneIds, ...body.dstZoneIds], sets.zones);
  if (!zoneCheck.ok)
    return { ok: false, message: "Unknown zone id in srcZoneIds/dstZoneIds", details: { offendingIds: zoneCheck.offending } };

  const addrCheck = checkIds([...body.srcAddrIds, ...body.dstAddrIds], sets.addrs);
  if (!addrCheck.ok)
    return { ok: false, message: "Unknown address object/group id in srcAddrIds/dstAddrIds", details: { offendingIds: addrCheck.offending } };

  const svcCheck = checkIds(body.serviceIds, sets.services);
  if (!svcCheck.ok)
    return { ok: false, message: "Unknown service object/group id in serviceIds", details: { offendingIds: svcCheck.offending } };

  const userCheck = checkIds(body.userIds, sets.users);
  if (!userCheck.ok)
    return { ok: false, message: "Unknown user id in userIds", details: { offendingIds: userCheck.offending } };

  if (body.scheduleId != null && !sets.schedules.has(body.scheduleId)) {
    return { ok: false, message: "Unknown scheduleId", details: { offendingIds: [body.scheduleId] } };
  }
  if (body.ipsPolicyId != null && !sets.ipsPolicies.has(body.ipsPolicyId)) {
    return { ok: false, message: "Unknown ipsPolicyId", details: { offendingIds: [body.ipsPolicyId] } };
  }
  if (body.qosPolicyId != null && !sets.qosPolicies.has(body.qosPolicyId)) {
    return { ok: false, message: "Unknown qosPolicyId", details: { offendingIds: [body.qosPolicyId] } };
  }
  return { ok: true };
}
