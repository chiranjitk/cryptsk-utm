/**
 * SD-WAN service (M20, spec 2.5) — SLA profiles, overlays, sites, paths and
 * path-selection policies, plus the SIMULATED probe cycle (the appliance
 * measures for real): a deterministic pseudo-random walk (±15% around current
 * values, hash-seeded per path + 15s bucket) re-evaluates every path of
 * enabled sites in enabled overlays against the overlay's first attached
 * policy SLA profile (fallback latency 150 / jitter 30 / loss 1.0).
 * All queries are tenant-scoped; mutations are audited by the route layer
 * which snapshots section `sdwan`.
 */

import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import type {
  SdwanOverlay,
  SdwanPath,
  SdwanPolicy,
  SdwanSite,
  SlaProfile,
} from "@prisma/client";
import type {
  OverlayCreate,
  OverlayUpdate,
  PathCreate,
  PathUpdate,
  PolicyCreate,
  PolicyUpdate,
  ProbeBody,
  SiteCreate,
  SiteUpdate,
  SlaProfileCreate,
  SlaProfileUpdate,
} from "@/lib/validators/sdwan";

// ── DTOs (mirrored in components/views/sdwan/sdwan-api.ts) ──────────────────

export type SlaAction = "switch" | "warn";
export type Topology = "hub_spoke" | "full_mesh";
export type Encryption = "wireguard" | "ipsec";
export type SiteRole = "hub" | "spoke";
export type WanInterface = "wan0" | "wan1" | "wan2";
export type PathLabel = "mpls" | "broadband" | "lte";
export type PathState = "up" | "degraded" | "down";
export type PreferredPath = "latency" | "jitter" | "loss" | "fixed";

export interface SlaProfileDTO {
  id: number;
  name: string;
  latencyMsMax: number;
  jitterMsMax: number;
  lossPctMax: number;
  actionOnBreach: SlaAction;
  policyCount: number;
  createdAt: string;
}

export interface OverlayDTO {
  id: number;
  name: string;
  topology: Topology;
  encryption: Encryption;
  enabled: boolean;
  siteCount: number;
  policyCount: number;
  createdAt: string;
}

export interface SiteDTO {
  id: number;
  overlayId: number;
  overlayName: string;
  name: string;
  role: SiteRole;
  publicIp: string;
  wgPubKey: string | null;
  region: string | null;
  enabled: boolean;
  pathCount: number;
  createdAt: string;
}

export interface PathDTO {
  id: number;
  siteId: number;
  siteName: string;
  wanInterface: WanInterface;
  label: PathLabel;
  latencyMs: number;
  jitterMs: number;
  lossPct: number;
  state: PathState;
  lastProbeAt: string;
}

export interface PolicyDTO {
  id: number;
  name: string;
  overlayId: number;
  matchApp: string | null;
  matchDscp: string | null;
  matchDestCidr: string | null;
  preferredPath: PreferredPath;
  fixedWanInterface: WanInterface | null;
  slaProfileId: number | null;
  slaProfileName: string | null;
  enabled: boolean;
  createdAt: string;
}

export interface SdwanStatsDTO {
  overlays: number;
  sites: number;
  pathsByState: { up: number; degraded: number; down: number };
  avgLatencyMs: number;
  worstPath: { siteName: string; wanInterface: WanInterface; latencyMs: number } | null;
}

export interface ProbeSummaryDTO {
  probed: number;
  up: number;
  degraded: number;
  down: number;
}

/** Global fallback thresholds when an overlay has no attached SLA profile. */
export const FALLBACK_SLA = { latencyMsMax: 150, jitterMsMax: 30, lossPctMax: 1.0 } as const;

// ── mapping helpers ─────────────────────────────────────────────────────────

function toSlaDTO(row: SlaProfile, policyCount = 0): SlaProfileDTO {
  return {
    id: row.id,
    name: row.name,
    latencyMsMax: row.latencyMsMax,
    jitterMsMax: row.jitterMsMax,
    lossPctMax: row.lossPctMax,
    actionOnBreach: row.actionOnBreach as SlaAction,
    policyCount,
    createdAt: row.createdAt.toISOString(),
  };
}

function toOverlayDTO(row: SdwanOverlay, siteCount = 0, policyCount = 0): OverlayDTO {
  return {
    id: row.id,
    name: row.name,
    topology: row.topology as Topology,
    encryption: row.encryption as Encryption,
    enabled: row.enabled,
    siteCount,
    policyCount,
    createdAt: row.createdAt.toISOString(),
  };
}

function toSiteDTO(row: SdwanSite, overlayName: string, pathCount = 0): SiteDTO {
  return {
    id: row.id,
    overlayId: row.overlayId,
    overlayName,
    name: row.name,
    role: row.role as SiteRole,
    publicIp: row.publicIp,
    wgPubKey: row.wgPubKey,
    region: row.region,
    enabled: row.enabled,
    pathCount,
    createdAt: row.createdAt.toISOString(),
  };
}

function toPathDTO(row: SdwanPath, siteName: string): PathDTO {
  return {
    id: row.id,
    siteId: row.siteId,
    siteName,
    wanInterface: row.wanInterface as WanInterface,
    label: row.label as PathLabel,
    latencyMs: row.latencyMs,
    jitterMs: row.jitterMs,
    lossPct: row.lossPct,
    state: row.state as PathState,
    lastProbeAt: row.lastProbeAt.toISOString(),
  };
}

function toPolicyDTO(row: SdwanPolicy, slaProfileName: string | null = null): PolicyDTO {
  return {
    id: row.id,
    name: row.name,
    overlayId: row.overlayId,
    matchApp: row.matchApp,
    matchDscp: row.matchDscp,
    matchDestCidr: row.matchDestCidr,
    preferredPath: row.preferredPath as PreferredPath,
    fixedWanInterface: (row.fixedWanInterface as WanInterface | null) ?? null,
    slaProfileId: row.slaProfileId,
    slaProfileName,
    enabled: row.enabled,
    createdAt: row.createdAt.toISOString(),
  };
}

async function requireOverlay(tenantId: number, overlayId: number): Promise<SdwanOverlay> {
  const overlay = await db.sdwanOverlay.findFirst({ where: { tenantId, id: overlayId } });
  if (!overlay) throw ApiError.notFound("Overlay not found");
  return overlay;
}

async function requireSite(tenantId: number, siteId: number): Promise<SdwanSite> {
  const site = await db.sdwanSite.findFirst({ where: { tenantId, id: siteId } });
  if (!site) throw ApiError.notFound("Site not found");
  return site;
}

async function requirePath(tenantId: number, pathId: number): Promise<SdwanPath> {
  const path = await db.sdwanPath.findFirst({ where: { tenantId, id: pathId } });
  if (!path) throw ApiError.notFound("Path not found");
  return path;
}

// ── SLA profiles ────────────────────────────────────────────────────────────

export async function listSlaProfiles(tenantId: number): Promise<SlaProfileDTO[]> {
  const rows = await db.slaProfile.findMany({ where: { tenantId }, orderBy: { name: "asc" } });
  const counts = await db.sdwanPolicy.groupBy({
    by: ["slaProfileId"],
    where: { tenantId, slaProfileId: { in: rows.map((r) => r.id) } },
    _count: { _all: true },
  });
  const byProfile = new Map<number, number>();
  for (const c of counts) {
    if (c.slaProfileId !== null) byProfile.set(c.slaProfileId, c._count._all);
  }
  return rows.map((r) => toSlaDTO(r, byProfile.get(r.id) ?? 0));
}

export async function createSlaProfile(tenantId: number, input: SlaProfileCreate): Promise<SlaProfileDTO> {
  const row = await db.slaProfile.create({ data: { tenantId, ...input } });
  return toSlaDTO(row);
}

export async function updateSlaProfile(
  tenantId: number,
  id: number,
  input: SlaProfileUpdate,
): Promise<SlaProfileDTO> {
  await db.slaProfile.findFirstOrThrow({ where: { tenantId, id } });
  const row = await db.slaProfile.update({ where: { id }, data: input });
  return toSlaDTO(row);
}

export async function deleteSlaProfile(tenantId: number, id: number): Promise<{ ok: true }> {
  const row = await db.slaProfile.findFirst({ where: { tenantId, id } });
  if (!row) throw ApiError.notFound("SLA profile not found");
  const referencing = await db.sdwanPolicy.findMany({
    where: { tenantId, slaProfileId: id },
    select: { name: true },
  });
  if (referencing.length > 0) {
    throw ApiError.conflict("SLA profile is referenced by policies and cannot be deleted", {
      referencedBy: referencing.map((p) => ({ ruleName: p.name, ruleType: "sdwan_policy" })),
    });
  }
  await db.slaProfile.delete({ where: { id } });
  return { ok: true };
}

// ── overlays ────────────────────────────────────────────────────────────────

export async function listOverlays(tenantId: number): Promise<OverlayDTO[]> {
  const rows = await db.sdwanOverlay.findMany({ where: { tenantId }, orderBy: { id: "asc" } });
  const ids = rows.map((r) => r.id);
  const [siteCounts, policyCounts] = await Promise.all([
    db.sdwanSite.groupBy({ by: ["overlayId"], where: { tenantId, overlayId: { in: ids } }, _count: { _all: true } }),
    db.sdwanPolicy.groupBy({ by: ["overlayId"], where: { tenantId, overlayId: { in: ids } }, _count: { _all: true } }),
  ]);
  const sitesBy = new Map(siteCounts.map((c) => [c.overlayId, c._count._all]));
  const policiesBy = new Map(policyCounts.map((c) => [c.overlayId, c._count._all]));
  return rows.map((r) => toOverlayDTO(r, sitesBy.get(r.id) ?? 0, policiesBy.get(r.id) ?? 0));
}

export async function createOverlay(tenantId: number, input: OverlayCreate): Promise<OverlayDTO> {
  const row = await db.sdwanOverlay.create({ data: { tenantId, ...input } });
  return toOverlayDTO(row);
}

export async function updateOverlay(
  tenantId: number,
  id: number,
  input: OverlayUpdate,
): Promise<OverlayDTO> {
  await db.sdwanOverlay.findFirstOrThrow({ where: { tenantId, id } });
  const row = await db.sdwanOverlay.update({ where: { id }, data: input });
  return toOverlayDTO(row);
}

export async function deleteOverlay(tenantId: number, id: number): Promise<{ ok: true }> {
  const overlay = await requireOverlay(tenantId, id);
  const [sites, policies] = await Promise.all([
    db.sdwanSite.findMany({ where: { tenantId, overlayId: id }, select: { name: true } }),
    db.sdwanPolicy.findMany({ where: { tenantId, overlayId: id }, select: { name: true } }),
  ]);
  if (sites.length > 0 || policies.length > 0) {
    throw ApiError.conflict(
      `Overlay "${overlay.name}" still has ${sites.length} site(s) and ${policies.length} policy(ies)`,
      {
        referencedBy: [
          ...sites.map((s) => ({ ruleName: s.name, ruleType: "sdwan_site" })),
          ...policies.map((p) => ({ ruleName: p.name, ruleType: "sdwan_policy" })),
        ],
      },
    );
  }
  await db.sdwanOverlay.delete({ where: { id } });
  return { ok: true };
}

// ── sites ───────────────────────────────────────────────────────────────────

export async function listSites(tenantId: number, overlayId?: number): Promise<SiteDTO[]> {
  const where = { tenantId, ...(overlayId !== undefined ? { overlayId } : {}) };
  const rows = await db.sdwanSite.findMany({ where, orderBy: [{ overlayId: "asc" }, { name: "asc" }] });
  const [overlays, pathCounts] = await Promise.all([
    db.sdwanOverlay.findMany({ where: { tenantId }, select: { id: true, name: true } }),
    db.sdwanPath.groupBy({
      by: ["siteId"],
      where: { tenantId, siteId: { in: rows.map((r) => r.id) } },
      _count: { _all: true },
    }),
  ]);
  const overlayNames = new Map(overlays.map((o) => [o.id, o.name]));
  const pathsBy = new Map(pathCounts.map((c) => [c.siteId, c._count._all]));
  return rows.map((r) => toSiteDTO(r, overlayNames.get(r.overlayId) ?? "?", pathsBy.get(r.id) ?? 0));
}

export async function createSite(tenantId: number, input: SiteCreate): Promise<SiteDTO> {
  const overlay = await requireOverlay(tenantId, input.overlayId);
  const row = await db.sdwanSite.create({ data: { tenantId, ...input } });
  return toSiteDTO(row, overlay.name);
}

export async function updateSite(tenantId: number, id: number, input: SiteUpdate): Promise<SiteDTO> {
  const existing = await requireSite(tenantId, id);
  if (input.overlayId !== undefined && input.overlayId !== existing.overlayId) {
    await requireOverlay(tenantId, input.overlayId);
  }
  const row = await db.sdwanSite.update({ where: { id }, data: input });
  const overlay = await requireOverlay(tenantId, row.overlayId);
  const pathCount = await db.sdwanPath.count({ where: { tenantId, siteId: row.id } });
  return toSiteDTO(row, overlay.name, pathCount);
}

export async function deleteSite(tenantId: number, id: number): Promise<{ ok: true }> {
  await requireSite(tenantId, id);
  // no FK relation on SdwanPath.siteId — cascade manually
  await db.sdwanPath.deleteMany({ where: { tenantId, siteId: id } });
  await db.sdwanSite.delete({ where: { id } });
  return { ok: true };
}

// ── paths ───────────────────────────────────────────────────────────────────

export async function listPaths(tenantId: number, siteId?: number): Promise<PathDTO[]> {
  const where = { tenantId, ...(siteId !== undefined ? { siteId } : {}) };
  const rows = await db.sdwanPath.findMany({
    where,
    orderBy: [{ siteId: "asc" }, { wanInterface: "asc" }],
  });
  const sites = await db.sdwanSite.findMany({ where: { tenantId }, select: { id: true, name: true } });
  const siteNames = new Map(sites.map((s) => [s.id, s.name]));
  return rows.map((r) => toPathDTO(r, siteNames.get(r.siteId) ?? "?"));
}

export async function createPath(tenantId: number, siteId: number, input: PathCreate): Promise<PathDTO> {
  const site = await requireSite(tenantId, siteId);
  const row = await db.sdwanPath.create({
    data: {
      tenantId,
      siteId,
      wanInterface: input.wanInterface,
      label: input.label,
      latencyMs: input.latencyMs,
      jitterMs: input.jitterMs,
      lossPct: input.lossPct,
      state: input.state,
      lastProbeAt: input.lastProbeAt ? new Date(input.lastProbeAt) : new Date(),
    },
  });
  return toPathDTO(row, site.name);
}

export async function updatePath(tenantId: number, id: number, input: PathUpdate): Promise<PathDTO> {
  const existing = await requirePath(tenantId, id);
  const { lastProbeAt, ...rest } = input;
  const row = await db.sdwanPath.update({
    where: { id },
    data: { ...rest, ...(lastProbeAt !== undefined ? { lastProbeAt: new Date(lastProbeAt) } : {}) },
  });
  const site = await db.sdwanSite.findFirst({ where: { tenantId, id: existing.siteId } });
  return toPathDTO(row, site?.name ?? "?");
}

export async function deletePath(tenantId: number, id: number): Promise<{ ok: true }> {
  await requirePath(tenantId, id);
  await db.sdwanPath.delete({ where: { id } });
  return { ok: true };
}

// ── simulated probe cycle (spec 2.5 — deterministic pseudo-random walk) ─────

/** FNV-1a-ish 32-bit hash over integers — stable across process restarts. */
function hash32(...nums: number[]): number {
  let h = 2166136261 >>> 0;
  for (const n of nums) {
    h = (h ^ (Math.floor(Math.abs(n)) >>> 0)) >>> 0;
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h >>> 0;
}

/** Deterministic unit in [0, 1) from a seed tuple. */
function unit(...nums: number[]): number {
  return hash32(...nums) / 4294967296;
}

function clamp(v: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, v));
}

/** Walk one metric ±15% around its current value, rounded to 1 decimal. */
function walk(current: number, seed: number, min: number, max: number): number {
  const factor = 0.85 + 0.3 * unit(seed);
  return Math.round(clamp(current * factor, min, max) * 10) / 10;
}

export async function probePaths(tenantId: number, body: ProbeBody): Promise<ProbeSummaryDTO> {
  // enabled sites of enabled overlays (optionally scoped to one overlay)
  const sites = await db.sdwanSite.findMany({
    where: {
      tenantId,
      enabled: true,
      ...(body.overlayId !== undefined ? { overlayId: body.overlayId } : {}),
    },
  });
  if (sites.length === 0) return { probed: 0, up: 0, degraded: 0, down: 0 };

  const overlayIds = [...new Set(sites.map((s) => s.overlayId))];
  const [overlays, policies, profiles, paths] = await Promise.all([
    db.sdwanOverlay.findMany({ where: { tenantId, id: { in: overlayIds }, enabled: true }, select: { id: true } }),
    db.sdwanPolicy.findMany({
      where: { tenantId, overlayId: { in: overlayIds } },
      orderBy: { id: "asc" },
      select: { overlayId: true, slaProfileId: true },
    }),
    db.slaProfile.findMany({ where: { tenantId } }),
    db.sdwanPath.findMany({ where: { tenantId, siteId: { in: sites.map((s) => s.id) } } }),
  ]);

  const liveOverlayIds = new Set(overlays.map((o) => o.id));
  const targets = sites.filter((s) => liveOverlayIds.has(s.overlayId));

  // per-overlay SLA thresholds: first attached policy with a profile, else fallback
  const profileById = new Map(profiles.map((p) => [p.id, p]));
  const slaByOverlay = new Map<number, { latencyMsMax: number; jitterMsMax: number; lossPctMax: number }>();
  for (const overlayId of overlayIds) {
    const firstWithSla = policies.find((p) => p.overlayId === overlayId && p.slaProfileId !== null);
    const profile = firstWithSla ? profileById.get(firstWithSla.slaProfileId ?? -1) : undefined;
    slaByOverlay.set(
      overlayId,
      profile
        ? { latencyMsMax: profile.latencyMsMax, jitterMsMax: profile.jitterMsMax, lossPctMax: profile.lossPctMax }
        : { ...FALLBACK_SLA },
    );
  }

  const bucket = Math.floor(Date.now() / 15_000); // 15s determinism window
  const summary: ProbeSummaryDTO = { probed: 0, up: 0, degraded: 0, down: 0 };
  const now = new Date();

  for (const path of paths) {
    const site = targets.find((s) => s.id === path.siteId);
    if (!site) continue;
    const sla = slaByOverlay.get(site.overlayId) ?? { ...FALLBACK_SLA };

    // deterministic probe-fail: ~3% of cycles mark the path down outright
    const probeFail = hash32(path.id, bucket, 7) % 100 < 3;

    const latencyMs = walk(path.latencyMs, hash32(path.id, bucket, 1), 1, 10_000);
    const jitterMs = walk(path.jitterMs, hash32(path.id, bucket, 2), 0, 2000);
    const lossPct = walk(path.lossPct, hash32(path.id, bucket, 3), 0, 100);

    let state: PathState;
    if (probeFail) {
      state = "down";
    } else {
      const breaches =
        (latencyMs > sla.latencyMsMax ? 1 : 0) +
        (jitterMs > sla.jitterMsMax ? 1 : 0) +
        (lossPct > sla.lossPctMax ? 1 : 0);
      state = breaches === 0 ? "up" : breaches < 3 ? "degraded" : "down";
    }

    await db.sdwanPath.update({
      where: { id: path.id },
      data: { latencyMs, jitterMs, lossPct, state, lastProbeAt: now },
    });

    summary.probed += 1;
    summary[state] += 1;
  }

  return summary;
}

// ── policies ────────────────────────────────────────────────────────────────

export async function listPolicies(tenantId: number): Promise<PolicyDTO[]> {
  const [rows, profiles] = await Promise.all([
    db.sdwanPolicy.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
    db.slaProfile.findMany({ where: { tenantId }, select: { id: true, name: true } }),
  ]);
  const profileNames = new Map(profiles.map((p) => [p.id, p.name]));
  return rows.map((r) =>
    toPolicyDTO(r, r.slaProfileId !== null ? (profileNames.get(r.slaProfileId) ?? null) : null),
  );
}

export async function createPolicy(tenantId: number, input: PolicyCreate): Promise<PolicyDTO> {
  await requireOverlay(tenantId, input.overlayId);
  if (input.slaProfileId !== undefined && input.slaProfileId !== null) {
    const sla = await db.slaProfile.findFirst({ where: { tenantId, id: input.slaProfileId } });
    if (!sla) throw ApiError.notFound("SLA profile not found");
  }
  const row = await db.sdwanPolicy.create({ data: { tenantId, ...input } });
  return toPolicyDTO(row);
}

export async function updatePolicy(tenantId: number, id: number, input: PolicyUpdate): Promise<PolicyDTO> {
  await db.sdwanPolicy.findFirstOrThrow({ where: { tenantId, id } });
  if (input.overlayId !== undefined) await requireOverlay(tenantId, input.overlayId);
  if (input.slaProfileId !== undefined && input.slaProfileId !== null) {
    const sla = await db.slaProfile.findFirst({ where: { tenantId, id: input.slaProfileId } });
    if (!sla) throw ApiError.notFound("SLA profile not found");
  }
  const row = await db.sdwanPolicy.update({ where: { id }, data: input });
  let slaProfileName: string | null = null;
  if (row.slaProfileId !== null) {
    const sla = await db.slaProfile.findFirst({ where: { tenantId, id: row.slaProfileId } });
    slaProfileName = sla?.name ?? null;
  }
  return toPolicyDTO(row, slaProfileName);
}

export async function deletePolicy(tenantId: number, id: number): Promise<{ ok: true }> {
  await db.sdwanPolicy.findFirstOrThrow({ where: { tenantId, id } });
  await db.sdwanPolicy.delete({ where: { id } });
  return { ok: true };
}

// ── stats ───────────────────────────────────────────────────────────────────

export async function getStats(tenantId: number): Promise<SdwanStatsDTO> {
  const [overlays, sites, stateGroups, avg, worst] = await Promise.all([
    db.sdwanOverlay.count({ where: { tenantId } }),
    db.sdwanSite.count({ where: { tenantId } }),
    db.sdwanPath.groupBy({ by: ["state"], where: { tenantId }, _count: { _all: true } }),
    db.sdwanPath.aggregate({ where: { tenantId }, _avg: { latencyMs: true } }),
    db.sdwanPath.findFirst({ where: { tenantId }, orderBy: { latencyMs: "desc" } }),
  ]);

  const pathsByState = { up: 0, degraded: 0, down: 0 };
  for (const g of stateGroups) {
    if (g.state === "up") pathsByState.up = g._count._all;
    else if (g.state === "degraded") pathsByState.degraded = g._count._all;
    else if (g.state === "down") pathsByState.down = g._count._all;
  }

  let worstPath: SdwanStatsDTO["worstPath"] = null;
  if (worst) {
    const site = await db.sdwanSite.findFirst({ where: { tenantId, id: worst.siteId }, select: { name: true } });
    worstPath = {
      siteName: site?.name ?? "?",
      wanInterface: worst.wanInterface as WanInterface,
      latencyMs: worst.latencyMs,
    };
  }

  return {
    overlays,
    sites,
    pathsByState,
    avgLatencyMs: Math.round((avg._avg.latencyMs ?? 0) * 10) / 10,
    worstPath,
  };
}
