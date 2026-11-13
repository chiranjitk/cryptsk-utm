/**
 * M19 seed — Dynamic Routing: BGP/OSPF (spec 2.6). Idempotent, tenantId 1:
 * BFD profile "standard" (300/300/3), prefix list "UPSTREAM-IN" (2 entries),
 * route map "UPSTREAM-PREF" (2 entries), community list "TRANSIT-COMM",
 * BGP neighbors upstream-1 (established, 14 prefixes, BFD on) / upstream-2
 * (idle), OSPF settings + interfaces lan0 (full) / dmz0 (init) and 8 RIB rows
 * across bgp/ospf/static/connected.
 *
 * Run via: bun prisma/seed-phase2.ts (orchestrator tolerates missing modules).
 */

import type { PrismaClient } from "@prisma/client";

const TENANT = 1;

const PREFIX_LIST_ENTRIES = [
  { seq: 10, action: "permit", prefix: "0.0.0.0/0", ge: null, le: null },
  { seq: 20, action: "deny", prefix: "10.0.0.0/8", ge: null, le: null },
];

const ROUTE_MAP_ENTRIES = [
  { seq: 10, action: "permit", matchPrefixListId: null, matchCommunity: null, setLocalPref: 200, setMetric: null, setCommunity: null },
  { seq: 20, action: "permit", matchPrefixListId: null, matchCommunity: "65000:100", setLocalPref: 150, setMetric: null, setCommunity: "65000:100" },
];

const RIB_ROWS = [
  { protocol: "bgp", prefix: "10.20.10.0/24", nextHop: "203.0.113.9", interfaceName: "wan0", metric: 0, localPref: 100, asPath: "65000 65010" },
  { protocol: "bgp", prefix: "10.20.20.0/24", nextHop: "203.0.113.9", interfaceName: "wan0", metric: 0, localPref: 100, asPath: "65000 65011" },
  { protocol: "ospf", prefix: "10.10.0.0/24", nextHop: "10.10.0.2", interfaceName: "lan0", metric: 10, localPref: null, asPath: null },
  { protocol: "ospf", prefix: "10.10.1.0/24", nextHop: "10.10.1.9", interfaceName: "dmz0", metric: 50, localPref: null, asPath: null },
  { protocol: "static", prefix: "0.0.0.0/0", nextHop: "203.0.113.1", interfaceName: "wan0", metric: 1, localPref: null, asPath: null },
  { protocol: "static", prefix: "10.90.0.0/16", nextHop: "10.10.0.254", interfaceName: "lan0", metric: 1, localPref: null, asPath: null },
  { protocol: "connected", prefix: "192.168.10.0/24", nextHop: "0.0.0.0", interfaceName: "lan0", metric: 0, localPref: null, asPath: null },
  { protocol: "connected", prefix: "198.51.100.0/24", nextHop: "0.0.0.0", interfaceName: "wan0", metric: 0, localPref: null, asPath: null },
];

export default async function seed(prisma: PrismaClient): Promise<string> {
  // ── BFD profile "standard" — upsert by (tenantId, name) ──────────────────
  const bfdProfile = await prisma.bfdProfile.upsert({
    where: { tenantId_name: { tenantId: TENANT, name: "standard" } },
    update: {},
    create: {
      tenantId: TENANT,
      name: "standard",
      rxIntervalMs: 300,
      txIntervalMs: 300,
      detectMultiplier: 3,
      enabled: true,
    },
  });

  // ── policy objects (entries stored as JSON) ──────────────────────────────
  const prefixList = await prisma.prefixList.upsert({
    where: { tenantId_name: { tenantId: TENANT, name: "UPSTREAM-IN" } },
    update: {},
    create: {
      tenantId: TENANT,
      name: "UPSTREAM-IN",
      family: "ipv4",
      entries: JSON.stringify(PREFIX_LIST_ENTRIES),
    },
  });

  const routeMap = await prisma.routeMap.upsert({
    where: { tenantId_name: { tenantId: TENANT, name: "UPSTREAM-PREF" } },
    update: {},
    create: {
      tenantId: TENANT,
      name: "UPSTREAM-PREF",
      entries: JSON.stringify(ROUTE_MAP_ENTRIES),
    },
  });

  await prisma.communityList.upsert({
    where: { tenantId_name: { tenantId: TENANT, name: "TRANSIT-COMM" } },
    update: {},
    create: {
      tenantId: TENANT,
      name: "TRANSIT-COMM",
      type: "standard",
      entries: JSON.stringify(["65000:100", "65000:200"]),
    },
  });

  // ── BGP neighbors — upsert by (tenantId, peerIp) ─────────────────────────
  await prisma.bgpNeighbor.upsert({
    where: { tenantId_peerIp: { tenantId: TENANT, peerIp: "203.0.113.9" } },
    update: {},
    create: {
      tenantId: TENANT,
      name: "upstream-1",
      remoteAs: 65000,
      peerIp: "203.0.113.9",
      peerIface: "wan0",
      password: "upstream1-md5-key",
      keepaliveSec: 60,
      holdtimeSec: 180,
      gracefulRestart: true,
      bfdEnabled: true,
      bfdProfileId: bfdProfile.id,
      prefixListInId: prefixList.id,
      routeMapInId: routeMap.id,
      ebgpMultihop: false,
      enabled: true,
      state: "established",
      uptimeSec: 3 * 86400 + 5 * 3600, // ~3d5h
      prefixesReceived: 14,
    },
  });

  await prisma.bgpNeighbor.upsert({
    where: { tenantId_peerIp: { tenantId: TENANT, peerIp: "198.51.100.17" } },
    update: {},
    create: {
      tenantId: TENANT,
      name: "upstream-2",
      remoteAs: 65001,
      peerIp: "198.51.100.17",
      peerIface: "wan1",
      keepaliveSec: 60,
      holdtimeSec: 180,
      gracefulRestart: false,
      bfdEnabled: false,
      ebgpMultihop: false,
      enabled: true,
      state: "idle",
      uptimeSec: 0,
      prefixesReceived: 0,
    },
  });

  // ── OSPF settings (single row per tenant) + interfaces ───────────────────
  const ospfSettings = await prisma.ospfSettings.findFirst({ where: { tenantId: TENANT } });
  if (!ospfSettings) {
    await prisma.ospfSettings.create({
      data: {
        tenantId: TENANT,
        routerId: "10.10.0.1",
        referenceBandwidth: 1000,
        gracefulRestart: true,
        enabled: true,
      },
    });
  }

  await prisma.ospfInterface.upsert({
    where: { tenantId_interfaceName: { tenantId: TENANT, interfaceName: "lan0" } },
    update: {},
    create: {
      tenantId: TENANT,
      interfaceName: "lan0",
      area: "0.0.0.0",
      helloSec: 10,
      deadSec: 40,
      cost: 10,
      networkType: "broadcast",
      passive: false,
      enabled: true,
      neighborState: "full",
      neighborIp: "10.10.0.2",
    },
  });

  await prisma.ospfInterface.upsert({
    where: { tenantId_interfaceName: { tenantId: TENANT, interfaceName: "dmz0" } },
    update: {},
    create: {
      tenantId: TENANT,
      interfaceName: "dmz0",
      area: "0.0.0.1",
      helloSec: 10,
      deadSec: 40,
      cost: 50,
      networkType: "broadcast",
      passive: false,
      enabled: true,
      neighborState: "init",
      neighborIp: "10.10.1.9",
    },
  });

  // ── RIB snapshot — upsert by (tenantId, protocol, prefix) ────────────────
  for (const row of RIB_ROWS) {
    await prisma.ribRoute.upsert({
      where: {
        tenantId_protocol_prefix: {
          tenantId: TENANT,
          protocol: row.protocol,
          prefix: row.prefix,
        },
      },
      update: {
        nextHop: row.nextHop,
        interfaceName: row.interfaceName,
        metric: row.metric,
        localPref: row.localPref,
        asPath: row.asPath,
      },
      create: { tenantId: TENANT, ...row },
    });
  }

  // ── summary from actual DB state (idempotent re-runs report real totals) ──
  const [bgpTotal, ospfTotal, plTotal, rmTotal, clTotal, bfdTotal, ribTotal] = await Promise.all([
    prisma.bgpNeighbor.count({ where: { tenantId: TENANT } }),
    prisma.ospfInterface.count({ where: { tenantId: TENANT } }),
    prisma.prefixList.count({ where: { tenantId: TENANT } }),
    prisma.routeMap.count({ where: { tenantId: TENANT } }),
    prisma.communityList.count({ where: { tenantId: TENANT } }),
    prisma.bfdProfile.count({ where: { tenantId: TENANT } }),
    prisma.ribRoute.count({ where: { tenantId: TENANT } }),
  ]);

  return `M19: ${bgpTotal} BGP neighbors, ${ospfTotal} OSPF ifaces, ${plTotal + rmTotal + clTotal} policy objects, ${bfdTotal} BFD profile, ${ribTotal} RIB routes`;
}
