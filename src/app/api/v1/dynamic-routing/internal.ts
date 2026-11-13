/**
 * M19 dynamic-routing route-internal helpers — DTO shaping (passwords are
 * write-only: never serialized out), referenced-object validation, policy
 * delete guards and the simulated FRR RIB regeneration. Consumed only by the
 * route files in this folder (same-directory relative import, per repo rules).
 */

import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { hashIpv4To } from "@/lib/validators/dynamic-routing";
import type {
  BgpNeighbor,
  CommunityList,
  PrefixList,
  RibRoute,
  RouteMap,
} from "@prisma/client";

// ── DTO shaping ──────────────────────────────────────────────────────────────

export type BgpNeighborDTO = Omit<BgpNeighbor, "password"> & { hasPassword: boolean };

/** Strip the session password — write-only, GET responses carry hasPassword. */
export function toNeighborDTO(row: BgpNeighbor): BgpNeighborDTO {
  const { password, ...rest } = row;
  return { ...rest, hasPassword: password !== null && password.length > 0 };
}

export type PrefixListDTO = PrefixList & { entryCount: number };
export type RouteMapDTO = RouteMap & { entryCount: number };
export type CommunityListDTO = CommunityList & { entryCount: number };

function withEntryCount<T extends { entries: string }>(row: T): T & { entryCount: number } {
  let count = 0;
  try {
    const parsed = JSON.parse(row.entries) as unknown;
    if (Array.isArray(parsed)) count = parsed.length;
  } catch {
    count = 0;
  }
  return { ...row, entryCount: count };
}

export const toPrefixListDTO = (row: PrefixList): PrefixListDTO => withEntryCount(row);
export const toRouteMapDTO = (row: RouteMap): RouteMapDTO => withEntryCount(row);
export const toCommunityListDTO = (row: CommunityList): CommunityListDTO => withEntryCount(row);

// ── neighbor reference validation (create / update) ─────────────────────────

export interface NeighborRefs {
  bfdProfileId?: number | null;
  prefixListInId?: number | null;
  prefixListOutId?: number | null;
  routeMapInId?: number | null;
  routeMapOutId?: number | null;
}

/** 400 with zod-style fieldErrors when a referenced object is missing or has
 *  the wrong family (prefix lists attached to neighbors must be ipv4). */
export async function assertNeighborRefs(tenantId: number, refs: NeighborRefs): Promise<void> {
  const fieldErrors: Record<string, string[]> = {};

  if (refs.bfdProfileId != null) {
    const profile = await db.bfdProfile.findFirst({ where: { id: refs.bfdProfileId, tenantId } });
    if (!profile) fieldErrors.bfdProfileId = ["BFD profile not found"];
  }
  const prefixFields = [
    ["prefixListInId", refs.prefixListInId],
    ["prefixListOutId", refs.prefixListOutId],
  ] as const;
  for (const [field, id] of prefixFields) {
    if (id == null) continue;
    const list = await db.prefixList.findFirst({ where: { id, tenantId } });
    if (!list) fieldErrors[field] = ["prefix list not found"];
    else if (list.family !== "ipv4") fieldErrors[field] = ["prefix list must be family ipv4 for BGP neighbors"];
  }
  const routeMapFields = [
    ["routeMapInId", refs.routeMapInId],
    ["routeMapOutId", refs.routeMapOutId],
  ] as const;
  for (const [field, id] of routeMapFields) {
    if (id == null) continue;
    const map = await db.routeMap.findFirst({ where: { id, tenantId } });
    if (!map) fieldErrors[field] = ["route map not found"];
  }

  if (Object.keys(fieldErrors).length > 0) {
    throw ApiError.validation("Referenced objects failed validation", { fieldErrors });
  }
}

// ── policy-object delete guards ──────────────────────────────────────────────

export type NeighborRefField =
  | "bfdProfileId"
  | "prefixListInId"
  | "prefixListOutId"
  | "routeMapInId"
  | "routeMapOutId";

/** 409 CONFLICT when a BGP neighbor still references the policy object. */
export async function assertNotReferencedByNeighbor(
  tenantId: number,
  field: NeighborRefField,
  id: number,
  label: string,
): Promise<void> {
  const users = await db.bgpNeighbor.findMany({
    where: { tenantId, [field]: id },
    select: { id: true, name: true, peerIp: true },
  });
  if (users.length > 0) {
    throw ApiError.conflict(`${label} is still referenced by BGP neighbors`, {
      referencedBy: users.map((u) => ({ ruleName: u.name, ruleType: `bgp ${u.peerIp}` })),
    });
  }
}

// ── simulated FRR RIB regeneration (POST /rib/refresh) ───────────────────────

export interface RibRegenResult {
  added: number;
  updated: number;
  removed: number;
  total: number;
  byProtocol: { bgp: number; ospf: number; static: number; connected: number };
}

interface RegenRow {
  protocol: "bgp" | "ospf" | "static" | "connected";
  prefix: string;
  nextHop: string;
  interfaceName: string;
  metric: number;
  localPref: number | null;
  asPath: string | null;
}

/**
 * Deterministic RIB snapshot: established BGP sessions contribute 2-6 prefixes
 * (hashed from peerIp+remoteAs, asPath "65000 <remoteAs>", localPref 100),
 * enabled OSPF interfaces contribute one 10.x.x.0/24 per area (metric = cost),
 * and static routes fan out into static (gateway set) / connected (interface
 * only) rows. Upserts by (tenant, protocol, prefix) and removes stale rows.
 */
export async function regenerateRib(tenantId: number): Promise<RibRegenResult> {
  const [neighbors, ifaces, statics] = await Promise.all([
    db.bgpNeighbor.findMany({ where: { tenantId, enabled: true, state: "established" } }),
    db.ospfInterface.findMany({ where: { tenantId, enabled: true }, orderBy: { id: "asc" } }),
    db.staticRoute.findMany({ where: { tenantId, enabled: true }, orderBy: { id: "asc" } }),
  ]);

  const rows: RegenRow[] = [];

  // BGP — 2-6 prefixes per established session
  for (const n of neighbors) {
    const key = `${n.peerIp}:${n.remoteAs}`;
    const count = hashIpv4To(key, 6, 2); // 2..6
    const second = hashIpv4To(key, 220, 10);
    const iface = n.peerIface ?? "wan0";
    for (let i = 0; i < count; i++) {
      const third = (hashIpv4To(`${key}:${i}`, 250, 1) + i * 7) % 251;
      rows.push({
        protocol: "bgp",
        prefix: `10.${second}.${third}.0/24`,
        nextHop: n.peerIp,
        interfaceName: iface,
        metric: 0,
        localPref: 100,
        asPath: `65000 ${n.remoteAs}`,
      });
    }
  }

  // OSPF — one 10.x.x.0/24 per enabled interface, derived from its area
  const ospfSeen = new Set<string>();
  for (const iface of ifaces) {
    const octets = iface.area.split(".").map((o) => Number(o) || 0);
    const b = octets[1] === 0 ? 10 : octets[1];
    const d = octets[3] ?? 0;
    const prefix = `10.${b}.${d}.0/24`;
    if (ospfSeen.has(prefix)) continue; // two ifaces in the same area → first wins
    ospfSeen.add(prefix);
    rows.push({
      protocol: "ospf",
      prefix,
      nextHop: iface.neighborIp ?? `10.${b}.${d}.1`,
      interfaceName: iface.interfaceName,
      metric: iface.cost,
      localPref: null,
      asPath: null,
    });
  }

  // Static / connected — gateway routes are static, interface-only are connected
  for (const r of statics) {
    const isStatic = r.gateway !== null && !r.blackhole;
    rows.push({
      protocol: isStatic ? "static" : "connected",
      prefix: r.destinationCidr,
      nextHop: isStatic ? r.gateway ?? "0.0.0.0" : r.blackhole ? "blackhole" : "0.0.0.0",
      interfaceName: r.interfaceName ?? "n/a",
      metric: r.distance,
      localPref: null,
      asPath: null,
    });
  }

  // ── sync: upsert regenerated rows, drop stale ones ──────────────────────
  const existing = await db.ribRoute.findMany({ where: { tenantId } });
  const byKey = new Map<string, RibRoute>();
  for (const row of existing) byKey.set(`${row.protocol}|${row.prefix}`, row);

  let added = 0;
  let updated = 0;
  const keptIds: number[] = [];

  for (const row of rows) {
    const match = byKey.get(`${row.protocol}|${row.prefix}`);
    if (match) {
      await db.ribRoute.update({
        where: { id: match.id },
        data: {
          nextHop: row.nextHop,
          interfaceName: row.interfaceName,
          metric: row.metric,
          localPref: row.localPref,
          asPath: row.asPath,
        },
      });
      keptIds.push(match.id);
      updated++;
    } else {
      const created = await db.ribRoute.create({ data: { tenantId, ...row } });
      keptIds.push(created.id);
      added++;
    }
  }

  const stale = existing.filter((row) => !keptIds.includes(row.id));
  if (stale.length > 0) {
    await db.ribRoute.deleteMany({ where: { id: { in: stale.map((row) => row.id) } } });
  }

  const byProtocol = { bgp: 0, ospf: 0, static: 0, connected: 0 };
  for (const row of rows) byProtocol[row.protocol]++;

  return { added, updated, removed: stale.length, total: rows.length, byProtocol };
}

// ── overview aggregate (GET /overview) ───────────────────────────────────────

export interface DrOverview {
  bgp: { established: number; total: number };
  ospf: { enabled: boolean; fullAdjacencies: number };
  rib: { bgp: number; ospf: number; static: number; connected: number };
  bfd: { profiles: number; neighborsUsing: number };
}

export async function computeOverview(tenantId: number): Promise<DrOverview> {
  const [bgpTotal, bgpEstablished, ifaces, settings, ribGroups, bfdProfiles, bfdNeighbors] =
    await Promise.all([
      db.bgpNeighbor.count({ where: { tenantId } }),
      db.bgpNeighbor.count({ where: { tenantId, state: "established" } }),
      db.ospfInterface.findMany({ where: { tenantId }, select: { neighborState: true } }),
      db.ospfSettings.findFirst({ where: { tenantId } }),
      db.ribRoute.groupBy({ by: ["protocol"], where: { tenantId }, _count: { _all: true } }),
      db.bfdProfile.count({ where: { tenantId } }),
      db.bgpNeighbor.count({ where: { tenantId, bfdEnabled: true } }),
    ]);

  const rib: DrOverview["rib"] = { bgp: 0, ospf: 0, static: 0, connected: 0 };
  for (const g of ribGroups) {
    if (g.protocol === "bgp" || g.protocol === "ospf" || g.protocol === "static" || g.protocol === "connected") {
      rib[g.protocol] = g._count._all;
    }
  }

  return {
    bgp: { established: bgpEstablished, total: bgpTotal },
    ospf: {
      enabled: settings?.enabled ?? false,
      fullAdjacencies: ifaces.filter((i) => i.neighborState === "full").length,
    },
    rib,
    bfd: { profiles: bfdProfiles, neighborsUsing: bfdNeighbors },
  };
}
