/**
 * M20 seed — SD-WAN (spec 2.5). Idempotent, tenantId=1: two SLA profiles
 * (voice 80/15/0.5 switch, business 150/30/1.0 warn), the "HQ mesh"
 * hub_spoke/wireguard overlay, hub "dc-hub" + spokes "branch-a"/"branch-b",
 * five WAN paths (hub wan0 mpls + wan1 broadband, branch-a broadband + a
 * degraded lte backup, branch-b broadband) and two path-selection policies
 * ("voice-prefer-latency" matching teams with the voice SLA, "backup-fixed-wan1"
 * pinned to wan1). Run via: bun prisma/seed-phase2.ts.
 */

import type { PrismaClient } from "@prisma/client";

const TENANT = 1;

export default async function seed(prisma: PrismaClient): Promise<string> {
  // ── SLA profiles ────────────────────────────────────────────────────────────
  const voiceSla = await prisma.slaProfile.upsert({
    where: { tenantId_name: { tenantId: TENANT, name: "voice" } },
    update: {},
    create: {
      tenantId: TENANT,
      name: "voice",
      latencyMsMax: 80,
      jitterMsMax: 15,
      lossPctMax: 0.5,
      actionOnBreach: "switch",
    },
  });

  await prisma.slaProfile.upsert({
    where: { tenantId_name: { tenantId: TENANT, name: "business" } },
    update: {},
    create: {
      tenantId: TENANT,
      name: "business",
      latencyMsMax: 150,
      jitterMsMax: 30,
      lossPctMax: 1.0,
      actionOnBreach: "warn",
    },
  });

  // ── overlay ─────────────────────────────────────────────────────────────────
  const overlay = await prisma.sdwanOverlay.upsert({
    where: { tenantId_name: { tenantId: TENANT, name: "HQ mesh" } },
    update: {},
    create: {
      tenantId: TENANT,
      name: "HQ mesh",
      topology: "hub_spoke",
      encryption: "wireguard",
      enabled: true,
    },
  });

  // ── sites (hub + 2 spokes) ──────────────────────────────────────────────────
  const hub = await prisma.sdwanSite.upsert({
    where: { tenantId_overlayId_name: { tenantId: TENANT, overlayId: overlay.id, name: "dc-hub" } },
    update: {},
    create: {
      tenantId: TENANT,
      overlayId: overlay.id,
      name: "dc-hub",
      role: "hub",
      publicIp: "203.0.113.1",
      region: "eu",
      enabled: true,
    },
  });

  const branchA = await prisma.sdwanSite.upsert({
    where: { tenantId_overlayId_name: { tenantId: TENANT, overlayId: overlay.id, name: "branch-a" } },
    update: {},
    create: {
      tenantId: TENANT,
      overlayId: overlay.id,
      name: "branch-a",
      role: "spoke",
      publicIp: "198.51.100.10",
      region: "eu",
      enabled: true,
    },
  });

  const branchB = await prisma.sdwanSite.upsert({
    where: { tenantId_overlayId_name: { tenantId: TENANT, overlayId: overlay.id, name: "branch-b" } },
    update: {},
    create: {
      tenantId: TENANT,
      overlayId: overlay.id,
      name: "branch-b",
      role: "spoke",
      publicIp: "198.51.100.11",
      region: "eu",
      enabled: true,
    },
  });

  // ── WAN paths (unique per site + wanInterface) ──────────────────────────────
  const paths: Array<{
    siteId: number;
    wanInterface: string;
    label: string;
    latencyMs: number;
    jitterMs: number;
    lossPct: number;
    state: string;
  }> = [
    { siteId: hub.id, wanInterface: "wan0", label: "mpls", latencyMs: 12, jitterMs: 2, lossPct: 0, state: "up" },
    { siteId: hub.id, wanInterface: "wan1", label: "broadband", latencyMs: 38, jitterMs: 6, lossPct: 0.2, state: "up" },
    { siteId: branchA.id, wanInterface: "wan0", label: "broadband", latencyMs: 45, jitterMs: 8, lossPct: 0.4, state: "up" },
    { siteId: branchA.id, wanInterface: "wan1", label: "lte", latencyMs: 120, jitterMs: 22, lossPct: 1.2, state: "degraded" },
    { siteId: branchB.id, wanInterface: "wan0", label: "broadband", latencyMs: 35, jitterMs: 7, lossPct: 0.1, state: "up" },
  ];

  for (const p of paths) {
    await prisma.sdwanPath.upsert({
      where: { tenantId_siteId_wanInterface: { tenantId: TENANT, siteId: p.siteId, wanInterface: p.wanInterface } },
      update: {},
      create: { tenantId: TENANT, lastProbeAt: new Date(), ...p },
    });
  }

  // ── path-selection policies ─────────────────────────────────────────────────
  await prisma.sdwanPolicy.upsert({
    where: { tenantId_name: { tenantId: TENANT, name: "voice-prefer-latency" } },
    update: {},
    create: {
      tenantId: TENANT,
      name: "voice-prefer-latency",
      overlayId: overlay.id,
      matchApp: "teams",
      matchDscp: null,
      matchDestCidr: null,
      preferredPath: "latency",
      fixedWanInterface: null,
      slaProfileId: voiceSla.id,
      enabled: true,
    },
  });

  await prisma.sdwanPolicy.upsert({
    where: { tenantId_name: { tenantId: TENANT, name: "backup-fixed-wan1" } },
    update: {},
    create: {
      tenantId: TENANT,
      name: "backup-fixed-wan1",
      overlayId: overlay.id,
      matchApp: null,
      matchDscp: null,
      matchDestCidr: null,
      preferredPath: "fixed",
      fixedWanInterface: "wan1",
      slaProfileId: null,
      enabled: true,
    },
  });

  return "M20: 1 overlay, 3 sites, 5 paths, 2 policies, 2 SLA profiles";
}
