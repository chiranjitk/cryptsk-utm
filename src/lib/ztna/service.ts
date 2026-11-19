/**
 * ZTNA service (Phase 4 §4.4) — DB-backed CRUD over the Phase 4 tables
 * (ZtnaApplication / ZtnaAccessPolicy / PostureProfile / DevicePostureCheck),
 * posture recording with the PURE engine verdict, the continuous-validation
 * loop and the user-to-resource access evaluation.
 *
 * Continuous validation (spec §4.4 "periodic re-check"): every posture check
 * row carries nextCheckAt = checkedAt + 60min. runContinuousValidation()
 * re-evaluates DUE rows (latest per device+profile whose nextCheckAt has
 * passed) by re-running the STORED raw results through evaluatePosture and
 * persisting a fresh snapshot row. The real probe transport — endpoint agent
 * or WMI/SSH per spec §4.4 — is OUT of console scope: until a fresh probe
 * result arrives via POST /posture-checks, the re-check replays the last
 * known raw results, so verdicts only change when the REQUIREMENTS change
 * (profile edited) or the device has never been fully observed.
 *
 * SQLite has no Prisma relation on the logical refs (appId, postureProfileId,
 * profileId), so name joins are explicit findMany maps — same pattern as the
 * incidents/threat-intel modules.
 */

import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import type { PageMeta } from "@/lib/api/envelope";
import {
  CHECK_KEYS,
  decideAccess,
  evaluatePosture,
  type AccessPolicyInput,
  type CheckKey,
  type PostureChecks,
  type PostureResults,
  type PostureVerdict,
} from "@/lib/ztna/engine";
import type {
  PostureCheckInput,
  PostureCheckQuery,
  PostureProfileInput,
  PostureProfileUpdate,
  ZtnaAppInput,
  ZtnaAppUpdate,
  ZtnaEvaluateBody,
  ZtnaPolicyInput,
  ZtnaPolicyQuery,
  ZtnaPolicyUpdate,
} from "@/lib/validators/ztna";

// ── constants ────────────────────────────────────────────────────────────────

/** Spec §4.4 continuous validation cadence — nextCheckAt = checkedAt + 60min. */
export const RECHECK_INTERVAL_MS = 60 * 60 * 1000;
/** Safety valve — at most this many stale checks are re-evaluated per run. */
const MAX_RECHECKS_PER_RUN = 200;

// ── DTOs ─────────────────────────────────────────────────────────────────────

export interface ZtnaAppDTO {
  id: number;
  name: string;
  host: string;
  port: number;
  protocol: "tcp" | "udp";
  group: string;
  policyCount: number;
  createdAt: string;
}

export interface ZtnaPolicyDTO {
  id: number;
  appId: number;
  appName: string;
  subjectType: "user" | "group" | "device";
  subjectRef: string;
  action: "allow" | "deny";
  postureProfileId: number | null;
  postureProfileName: string | null;
  schedule: string;
  enabled: boolean;
  createdAt: string;
}

export interface PostureProfileDTO {
  id: number;
  name: string;
  checks: PostureChecks;
  policyCount: number;
  createdAt: string;
}

export interface PostureCheckDTO {
  id: number;
  deviceId: string;
  profileId: number;
  profileName: string;
  results: PostureResults;
  verdict: PostureVerdict;
  failedChecks: CheckKey[];
  unknownChecks: CheckKey[];
  checkedAt: string;
  nextCheckAt: string | null;
}

export interface ZtnaStats {
  apps: number;
  policies: number;
  enabledPolicies: number;
  profiles: number;
  /** latest check per device — compliance pie data */
  compliance: { compliant: number; nonCompliant: number; unknown: number };
  /** latest rows per device+profile whose re-check window has elapsed */
  staleChecks: number;
  recentDenials: Array<{
    at: string;
    user: string | null;
    deviceId: string | null;
    appName: string | null;
    matchedPolicyId: number | null;
    reason: string;
  }>;
}

// ── JSON shaping helpers ─────────────────────────────────────────────────────

function parseObject<T>(raw: string | null | undefined): T {
  if (!raw) return {} as T;
  try {
    const v = JSON.parse(raw);
    return v && typeof v === "object" && !Array.isArray(v) ? (v as T) : ({} as T);
  } catch {
    return {} as T;
  }
}

function isUniqueViolation(err: unknown): boolean {
  return typeof err === "object" && err !== null && (err as { code?: unknown }).code === "P2002";
}

type AppRow = { id: number; tenantId: number; name: string; host: string; port: number; protocol: string; group: string; createdAt: Date };

function toAppDTO(row: AppRow, policyCount = 0): ZtnaAppDTO {
  return {
    id: row.id,
    name: row.name,
    host: row.host,
    port: row.port,
    protocol: row.protocol === "udp" ? "udp" : "tcp",
    group: row.group,
    policyCount,
    createdAt: row.createdAt.toISOString(),
  };
}

// ════════════════════════════════════════════════════════════════════════════
// applications
// ════════════════════════════════════════════════════════════════════════════

export async function listApps(tenantId: number): Promise<ZtnaAppDTO[]> {
  const [rows, counts] = await Promise.all([
    db.ztnaApplication.findMany({ where: { tenantId }, orderBy: { name: "asc" } }),
    db.ztnaAccessPolicy.groupBy({ by: ["appId"], where: { tenantId }, _count: { _all: true } }),
  ]);
  const countByApp = new Map(counts.map((c) => [c.appId, c._count._all]));
  return rows.map((r) => toAppDTO(r, countByApp.get(r.id) ?? 0));
}

export async function getApp(tenantId: number, id: number): Promise<ZtnaAppDTO> {
  const row = await db.ztnaApplication.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("ZTNA application not found");
  const policyCount = await db.ztnaAccessPolicy.count({ where: { tenantId, appId: id } });
  return toAppDTO(row, policyCount);
}

export async function createApp(tenantId: number, input: ZtnaAppInput): Promise<ZtnaAppDTO> {
  const dup = await db.ztnaApplication.findFirst({ where: { tenantId, name: input.name } });
  if (dup) throw ApiError.conflict(`ZTNA application '${input.name}' already exists`);
  const row = await db.ztnaApplication.create({
    data: {
      tenantId,
      name: input.name,
      host: input.host,
      port: input.port ?? 443,
      protocol: input.protocol ?? "tcp",
      group: input.group ?? "",
    },
  });
  return toAppDTO(row, 0);
}

export async function updateApp(tenantId: number, id: number, patch: ZtnaAppUpdate): Promise<ZtnaAppDTO> {
  const row = await db.ztnaApplication.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("ZTNA application not found");
  if (patch.name && patch.name !== row.name) {
    const dup = await db.ztnaApplication.findFirst({ where: { tenantId, name: patch.name } });
    if (dup) throw ApiError.conflict(`ZTNA application '${patch.name}' already exists`);
  }
  const updated = await db.ztnaApplication.update({ where: { id: row.id }, data: patch });
  const policyCount = await db.ztnaAccessPolicy.count({ where: { tenantId, appId: id } });
  return toAppDTO(updated, policyCount);
}

/**
 * DELETE — refuse while access policies still reference the app (logical
 * ref, no FK cascade — a dangling appId would silently orphan rules).
 */
export async function deleteApp(tenantId: number, id: number): Promise<{ ok: true }> {
  const row = await db.ztnaApplication.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("ZTNA application not found");
  const refs = await db.ztnaAccessPolicy.count({ where: { tenantId, appId: id } });
  if (refs > 0) {
    throw ApiError.conflict(`Application '${row.name}' still has ${refs} access polic${refs === 1 ? "y" : "ies"} — delete them first`);
  }
  await db.ztnaApplication.delete({ where: { id: row.id } });
  return { ok: true };
}

// ════════════════════════════════════════════════════════════════════════════
// access policies
// ════════════════════════════════════════════════════════════════════════════

type PolicyRow = {
  id: number;
  tenantId: number;
  appId: number;
  subjectType: string;
  subjectRef: string;
  action: string;
  postureProfileId: number | null;
  schedule: string;
  enabled: boolean;
  createdAt: Date;
};

function toPolicyDTO(
  row: PolicyRow,
  appNames: Map<number, string>,
  profileNames: Map<number, string>,
): ZtnaPolicyDTO {
  return {
    id: row.id,
    appId: row.appId,
    appName: appNames.get(row.appId) ?? `#${row.appId}`,
    subjectType: row.subjectType as "user" | "group" | "device",
    subjectRef: row.subjectRef,
    action: row.action === "deny" ? "deny" : "allow",
    postureProfileId: row.postureProfileId,
    postureProfileName: row.postureProfileId !== null ? (profileNames.get(row.postureProfileId) ?? `#${row.postureProfileId}`) : null,
    schedule: row.schedule,
    enabled: row.enabled,
    createdAt: row.createdAt.toISOString(),
  };
}

async function joinMaps(tenantId: number): Promise<{ appNames: Map<number, string>; profileNames: Map<number, string> }> {
  const [apps, profiles] = await Promise.all([
    db.ztnaApplication.findMany({ where: { tenantId }, select: { id: true, name: true } }),
    db.postureProfile.findMany({ where: { tenantId }, select: { id: true, name: true } }),
  ]);
  return {
    appNames: new Map(apps.map((a) => [a.id, a.name])),
    profileNames: new Map(profiles.map((p) => [p.id, p.name])),
  };
}

export async function listPolicies(tenantId: number, query: ZtnaPolicyQuery): Promise<ZtnaPolicyDTO[]> {
  const [rows, maps] = await Promise.all([
    db.ztnaAccessPolicy.findMany({
      where: { tenantId, ...(query.appId ? { appId: query.appId } : {}) },
      orderBy: [{ appId: "asc" }, { id: "asc" }],
    }),
    joinMaps(tenantId),
  ]);
  return rows.map((r) => toPolicyDTO(r, maps.appNames, maps.profileNames));
}

export async function getPolicy(tenantId: number, id: number): Promise<ZtnaPolicyDTO> {
  const row = await db.ztnaAccessPolicy.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("ZTNA access policy not found");
  const maps = await joinMaps(tenantId);
  return toPolicyDTO(row, maps.appNames, maps.profileNames);
}

async function assertAppExists(tenantId: number, appId: number): Promise<void> {
  const app = await db.ztnaApplication.findFirst({ where: { id: appId, tenantId }, select: { id: true } });
  if (!app) throw ApiError.validation(`Unknown ZTNA application #${appId}`);
}

async function assertProfileExists(tenantId: number, profileId: number): Promise<void> {
  const profile = await db.postureProfile.findFirst({ where: { id: profileId, tenantId }, select: { id: true } });
  if (!profile) throw ApiError.validation(`Unknown posture profile #${profileId}`);
}

export async function createPolicy(tenantId: number, input: ZtnaPolicyInput): Promise<ZtnaPolicyDTO> {
  await assertAppExists(tenantId, input.appId);
  if (input.postureProfileId != null) await assertProfileExists(tenantId, input.postureProfileId);
  const row = await db.ztnaAccessPolicy.create({
    data: {
      tenantId,
      appId: input.appId,
      subjectType: input.subjectType ?? "user",
      subjectRef: input.subjectRef,
      action: input.action ?? "allow",
      postureProfileId: input.postureProfileId ?? null,
      schedule: input.schedule ?? "",
      enabled: input.enabled ?? true,
    },
  });
  const maps = await joinMaps(tenantId);
  return toPolicyDTO(row, maps.appNames, maps.profileNames);
}

export async function updatePolicy(tenantId: number, id: number, patch: ZtnaPolicyUpdate): Promise<ZtnaPolicyDTO> {
  const row = await db.ztnaAccessPolicy.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("ZTNA access policy not found");
  if (patch.appId !== undefined) await assertAppExists(tenantId, patch.appId);
  if (patch.postureProfileId != null) await assertProfileExists(tenantId, patch.postureProfileId);
  const updated = await db.ztnaAccessPolicy.update({ where: { id: row.id }, data: patch });
  const maps = await joinMaps(tenantId);
  return toPolicyDTO(updated, maps.appNames, maps.profileNames);
}

export async function deletePolicy(tenantId: number, id: number): Promise<{ ok: true }> {
  const row = await db.ztnaAccessPolicy.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("ZTNA access policy not found");
  await db.ztnaAccessPolicy.delete({ where: { id: row.id } });
  return { ok: true };
}

// ════════════════════════════════════════════════════════════════════════════
// posture profiles
// ════════════════════════════════════════════════════════════════════════════

type ProfileRow = { id: number; tenantId: number; name: string; checks: string; createdAt: Date };

function toProfileDTO(row: ProfileRow, policyCount = 0): PostureProfileDTO {
  return {
    id: row.id,
    name: row.name,
    checks: parseObject<PostureChecks>(row.checks),
    policyCount,
    createdAt: row.createdAt.toISOString(),
  };
}

export async function listPostureProfiles(tenantId: number): Promise<PostureProfileDTO[]> {
  const [rows, counts] = await Promise.all([
    db.postureProfile.findMany({ where: { tenantId }, orderBy: { name: "asc" } }),
    db.ztnaAccessPolicy.groupBy({ by: ["postureProfileId"], where: { tenantId, postureProfileId: { not: null } }, _count: { _all: true } }),
  ]);
  const countByProfile = new Map(counts.map((c) => [c.postureProfileId ?? 0, c._count._all]));
  return rows.map((r) => toProfileDTO(r, countByProfile.get(r.id) ?? 0));
}

export async function getPostureProfile(tenantId: number, id: number): Promise<PostureProfileDTO> {
  const row = await db.postureProfile.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("Posture profile not found");
  const policyCount = await db.ztnaAccessPolicy.count({ where: { tenantId, postureProfileId: id } });
  return toProfileDTO(row, policyCount);
}

export async function createPostureProfile(tenantId: number, input: PostureProfileInput): Promise<PostureProfileDTO> {
  const dup = await db.postureProfile.findFirst({ where: { tenantId, name: input.name } });
  if (dup) throw ApiError.conflict(`Posture profile '${input.name}' already exists`);
  const row = await db.postureProfile.create({
    data: { tenantId, name: input.name, checks: JSON.stringify(input.checks ?? {}) },
  });
  return toProfileDTO(row, 0);
}

export async function updatePostureProfile(
  tenantId: number,
  id: number,
  patch: PostureProfileUpdate,
): Promise<PostureProfileDTO> {
  const row = await db.postureProfile.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("Posture profile not found");
  if (patch.name && patch.name !== row.name) {
    const dup = await db.postureProfile.findFirst({ where: { tenantId, name: patch.name } });
    if (dup) throw ApiError.conflict(`Posture profile '${patch.name}' already exists`);
  }
  const updated = await db.postureProfile.update({
    where: { id: row.id },
    data: {
      ...(patch.name !== undefined ? { name: patch.name } : {}),
      ...(patch.checks !== undefined ? { checks: JSON.stringify(patch.checks) } : {}),
    },
  });
  const policyCount = await db.ztnaAccessPolicy.count({ where: { tenantId, postureProfileId: id } });
  return toProfileDTO(updated, policyCount);
}

/**
 * DELETE — refuse while access policies attach the profile (dangling
 * postureProfileId would silently disable the posture gate). Historical
 * device_posture_checks rows keep their profileId as an immutable snapshot.
 */
export async function deletePostureProfile(tenantId: number, id: number): Promise<{ ok: true }> {
  const row = await db.postureProfile.findFirst({ where: { id, tenantId } });
  if (!row) throw ApiError.notFound("Posture profile not found");
  const refs = await db.ztnaAccessPolicy.count({ where: { tenantId, postureProfileId: id } });
  if (refs > 0) {
    throw ApiError.conflict(`Posture profile '${row.name}' is attached to ${refs} access polic${refs === 1 ? "y" : "ies"} — detach them first`);
  }
  await db.postureProfile.delete({ where: { id: row.id } });
  return { ok: true };
}

// ════════════════════════════════════════════════════════════════════════════
// posture checks — record, list (latest per device), continuous validation
// ════════════════════════════════════════════════════════════════════════════

type CheckRow = {
  id: number;
  tenantId: number;
  deviceId: string;
  profileId: number;
  results: string;
  verdict: string;
  checkedAt: Date;
  nextCheckAt: Date | null;
};

function toCheckDTO(row: CheckRow, profile: ProfileRow | undefined): PostureCheckDTO {
  const results = parseObject<PostureResults>(row.results);
  const profileChecks = profile ? parseObject<PostureChecks>(profile.checks) : {};
  const ev = evaluatePosture(profileChecks, results);
  return {
    id: row.id,
    deviceId: row.deviceId,
    profileId: row.profileId,
    profileName: profile?.name ?? `#${row.profileId}`,
    results,
    verdict: row.verdict as PostureVerdict,
    failedChecks: ev.failedChecks,
    unknownChecks: ev.unknownChecks,
    checkedAt: row.checkedAt.toISOString(),
    nextCheckAt: row.nextCheckAt ? row.nextCheckAt.toISOString() : null,
  };
}

/**
 * Record one posture evaluation (manual console entry or agent transport).
 * Raw results are validated against CHECK_KEYS, run through the PURE
 * evaluatePosture with the profile's requirement set, and persisted with
 * nextCheckAt = checkedAt + 60min (the continuous-validation cadence).
 */
export async function recordPostureCheck(
  tenantId: number,
  input: PostureCheckInput,
): Promise<PostureCheckDTO> {
  const profile = await db.postureProfile.findFirst({ where: { id: input.profileId, tenantId } });
  if (!profile) throw ApiError.notFound("Posture profile not found");

  const rawResults = input.results ?? {};
  const unknownKeys = Object.keys(rawResults).filter((k) => !CHECK_KEYS.includes(k as CheckKey));
  if (unknownKeys.length > 0) {
    throw ApiError.validation(`Unknown posture check key(s): ${unknownKeys.join(", ")} — allowed: ${CHECK_KEYS.join(", ")}`);
  }
  const deviceId = input.deviceId.trim();
  if (!deviceId) throw ApiError.validation("Device id is required");

  const results = rawResults as PostureResults;
  const profileChecks = parseObject<PostureChecks>(profile.checks);
  const ev = evaluatePosture(profileChecks, results);
  const now = new Date();
  const row = await db.devicePostureCheck.create({
    data: {
      tenantId,
      deviceId,
      profileId: profile.id,
      results: JSON.stringify(results),
      verdict: ev.verdict,
      checkedAt: now,
      nextCheckAt: new Date(now.getTime() + RECHECK_INTERVAL_MS),
    },
  });
  return toCheckDTO(row, profile);
}

/**
 * GET support — latest check per device (optionally scoped to one deviceId),
 * server-paged. groupBy deviceId → max(id) (service always stamps checkedAt
 * = now at creation, so id order == recency), then the rows themselves.
 */
export async function listLatestPostureChecks(
  tenantId: number,
  query: PostureCheckQuery,
): Promise<{ data: PostureCheckDTO[]; meta: PageMeta }> {
  const deviceWhere = { tenantId, ...(query.deviceId ? { deviceId: query.deviceId } : {}) };
  const [groups, profiles] = await Promise.all([
    db.devicePostureCheck.groupBy({ by: ["deviceId"], where: deviceWhere, _max: { id: true } }),
    db.postureProfile.findMany({ where: { tenantId }, select: { id: true, name: true, checks: true } }),
  ]);
  const latestIds = groups.map((g) => g._max.id).filter((v): v is number => typeof v === "number");
  // tenantId in the follow-up filter (audit fix F-d): ids came from a scoped
  // groupBy, but the explicit tenantId keeps the read tenant-safe regardless
  const rows = latestIds.length
    ? await db.devicePostureCheck.findMany({ where: { tenantId, id: { in: latestIds } } })
    : [];
  rows.sort((a, b) => b.checkedAt.getTime() - a.checkedAt.getTime() || b.id - a.id);

  const total = rows.length;
  const page = rows.slice((query.page - 1) * query.limit, (query.page - 1) * query.limit + query.limit);
  const profileById = new Map(profiles.map((p) => [p.id, p as ProfileRow]));
  return {
    data: page.map((r) => toCheckDTO(r, profileById.get(r.profileId))),
    meta: {
      page: query.page,
      limit: query.limit,
      total,
      totalPages: Math.max(1, Math.ceil(total / query.limit)),
    },
  };
}

export interface ContinuousValidationResult {
  /** devices+profiles re-evaluated this run */
  rechecked: number;
  /** how many flipped verdict */
  changed: number;
  results: Array<{ deviceId: string; profileId: number; previousVerdict: PostureVerdict; verdict: PostureVerdict; changed: boolean }>;
  /** audit fix L24 — set when a parallel validate run holds the in-flight claim */
  skipped?: "already-running";
}

/**
 * Continuous validation (spec §4.4 "periodic re-check"). Finds the LATEST
 * check per (deviceId, profileId) whose nextCheckAt has elapsed and re-runs
 * its stored raw results through evaluatePosture, persisting a fresh row.
 *
 * NOTE: the real probe transport (endpoint agent / WMI / SSH probe per spec
 * §4.4) is out of console scope — the re-check replays the last known raw
 * results until a new probe result is POSTed to /posture-checks. Triggered
 * EXPLICITLY via POST /api/v1/ztna/posture-checks/validate (audit fix F-d:
 * GET /posture-checks no longer mutates — reads are side-effect free).
 */
export async function runContinuousValidation(tenantId: number): Promise<ContinuousValidationResult> {
  // audit fix L24 — in-flight guard: two concurrent validate POSTs would both
  // re-evaluate the same stale rows and create duplicate snapshot rows. The
  // per-tenant claim flips to false only after the run completes; a second
  // caller inside that window gets an honest "already running" outcome.
  const inflightKey = `ztna-validate:${tenantId}`;
  if (ztnaValidateInflight.get(inflightKey)) {
    return { rechecked: 0, changed: 0, results: [], skipped: "already-running" };
  }
  ztnaValidateInflight.set(inflightKey, true);
  try {
    return await runContinuousValidationInner(tenantId);
  } finally {
    ztnaValidateInflight.delete(inflightKey);
  }
}

/** In-process in-flight claims (per process — enough to dedupe the operator
 *  double-click / parallel POST burst; multi-instance dedupe is future work). */
const ztnaValidateInflight = new Map<string, true>();

async function runContinuousValidationInner(tenantId: number): Promise<ContinuousValidationResult> {
  const now = new Date();
  // only the LATEST row per (deviceId, profileId) is live state — older
  // snapshots are history and must not spawn duplicate re-checks
  const groups = await db.devicePostureCheck.groupBy({
    by: ["deviceId", "profileId"],
    where: { tenantId },
    _max: { id: true },
  });
  const latestIds = groups.map((g) => g._max.id).filter((v): v is number => typeof v === "number");
  if (latestIds.length === 0) return { rechecked: 0, changed: 0, results: [] };

  const stale = (await db.devicePostureCheck.findMany({
    where: { id: { in: latestIds }, nextCheckAt: { lte: now } },
    orderBy: { id: "asc" },
    take: MAX_RECHECKS_PER_RUN,
  })) as CheckRow[];
  if (stale.length === 0) return { rechecked: 0, changed: 0, results: [] };

  const profiles = await db.postureProfile.findMany({
    where: { tenantId, id: { in: [...new Set(stale.map((r) => r.profileId))] } },
    select: { id: true, name: true, checks: true },
  });
  const profileById = new Map(profiles.map((p) => [p.id, p as ProfileRow]));

  const results: ContinuousValidationResult["results"] = [];
  let changed = 0;
  for (const row of stale) {
    const profile = profileById.get(row.profileId);
    const profileChecks = profile ? parseObject<PostureChecks>(profile.checks) : {};
    const ev = evaluatePosture(profileChecks, parseObject<PostureResults>(row.results));
    const previousVerdict = row.verdict as PostureVerdict;
    const flipped = ev.verdict !== previousVerdict;
    if (flipped) changed++;
    await db.devicePostureCheck.create({
      data: {
        tenantId,
        deviceId: row.deviceId,
        profileId: row.profileId,
        results: row.results, // stored raw results replayed verbatim (probe transport out of scope)
        verdict: ev.verdict,
        checkedAt: now,
        nextCheckAt: new Date(now.getTime() + RECHECK_INTERVAL_MS),
      },
    });
    results.push({ deviceId: row.deviceId, profileId: row.profileId, previousVerdict, verdict: ev.verdict, changed: flipped });
  }
  return { rechecked: results.length, changed, results };
}

// ════════════════════════════════════════════════════════════════════════════
// access evaluation (user-to-resource, spec §4.4)
// ════════════════════════════════════════════════════════════════════════════

/**
 * Resolve the device's CURRENT posture verdict for evaluation: the latest
 * check among the posture profiles the app's enabled policies actually gate
 * on; fall back to the device's latest check on any profile; never checked →
 * unknown (fail-closed).
 */
async function resolvePostureVerdict(
  tenantId: number,
  deviceId: string | undefined,
  gatedProfileIds: number[],
): Promise<PostureVerdict> {
  if (!deviceId) return "unknown";
  const scoped = gatedProfileIds.length
    ? await db.devicePostureCheck.findFirst({
        where: { tenantId, deviceId, profileId: { in: gatedProfileIds } },
        orderBy: [{ checkedAt: "desc" }, { id: "desc" }],
      })
    : null;
  const row =
    scoped ??
    (await db.devicePostureCheck.findFirst({
      where: { tenantId, deviceId },
      orderBy: [{ checkedAt: "desc" }, { id: "desc" }],
    }));
  return (row?.verdict as PostureVerdict | undefined) ?? "unknown";
}

export interface ZtnaEvaluationResult {
  appId: number;
  appName: string;
  decision: "allow" | "deny";
  matchedPolicyId: number | null;
  matchedPolicyRef: string | null;
  postureVerdict: PostureVerdict;
  reason: string;
  evaluatedAt: string;
}

export async function evaluateAccess(tenantId: number, input: ZtnaEvaluateBody): Promise<ZtnaEvaluationResult> {
  const app = await db.ztnaApplication.findFirst({ where: { id: input.appId, tenantId } });
  if (!app) throw ApiError.notFound("ZTNA application not found");

  const policies = await db.ztnaAccessPolicy.findMany({
    where: { tenantId, appId: app.id, enabled: true },
    orderBy: { id: "asc" },
  });

  const gatedProfileIds = [
    ...new Set(policies.map((p) => p.postureProfileId).filter((v): v is number => v !== null)),
  ];
  const deviceId = input.subject.deviceId?.trim() || undefined;
  const postureVerdict = await resolvePostureVerdict(tenantId, deviceId, gatedProfileIds);

  const enginePolicies: AccessPolicyInput[] = policies.map((p) => ({
    id: p.id,
    appId: p.appId,
    subjectType: p.subjectType as AccessPolicyInput["subjectType"],
    subjectRef: p.subjectRef,
    action: p.action as AccessPolicyInput["action"],
    postureProfileId: p.postureProfileId,
    enabled: p.enabled,
  }));

  const decision = decideAccess({
    policies: enginePolicies,
    subject: {
      user: input.subject.user?.trim() || undefined,
      groups: input.subject.groups ?? [],
      deviceId,
    },
    app: { id: app.id },
    postureVerdict,
  });
  const matched = policies.find((p) => p.id === decision.matchedPolicyId);
  // schedule is DISPLAY-ONLY (spec §4.4 — clock evaluation out of console
  // scope); surface that honestly on the matched policy (audit fix F-d)
  const reason =
    matched && matched.schedule.trim() ? `${decision.reason} (schedule not enforced)` : decision.reason;
  return {
    appId: app.id,
    appName: app.name,
    decision: decision.decision,
    matchedPolicyId: decision.matchedPolicyId,
    matchedPolicyRef: matched ? matched.subjectRef : null,
    postureVerdict,
    reason,
    evaluatedAt: new Date().toISOString(),
  };
}

// ════════════════════════════════════════════════════════════════════════════
// stats (console strip)
// ════════════════════════════════════════════════════════════════════════════

interface EvaluateAuditAfter {
  decision?: string;
  reason?: string;
  matchedPolicyId?: number | null;
  user?: string | null;
  deviceId?: string | null;
  appName?: string | null;
}

export async function getZtnaStats(tenantId: number): Promise<ZtnaStats> {
  const now = new Date();
  const [apps, policies, enabledPolicies, profiles, latestGroups, deniedAudits] = await Promise.all([
    db.ztnaApplication.count({ where: { tenantId } }),
    db.ztnaAccessPolicy.count({ where: { tenantId } }),
    db.ztnaAccessPolicy.count({ where: { tenantId, enabled: true } }),
    db.postureProfile.count({ where: { tenantId } }),
    db.devicePostureCheck.groupBy({ by: ["deviceId"], where: { tenantId }, _max: { id: true } }),
    db.auditLog.findMany({
      where: { tenantId, action: "ztna.evaluate", result: "success" },
      orderBy: { id: "desc" },
      take: 40,
    }),
  ]);

  const latestIds = latestGroups.map((g) => g._max.id).filter((v): v is number => typeof v === "number");
  // tenantId in the follow-up filter (audit fix F-d — tenant-safe read)
  const latestRows = latestIds.length
    ? await db.devicePostureCheck.findMany({
        where: { tenantId, id: { in: latestIds } },
        select: { id: true, verdict: true, nextCheckAt: true },
      })
    : [];

  const compliance = { compliant: 0, nonCompliant: 0, unknown: 0 };
  let staleChecks = 0;
  for (const row of latestRows) {
    if (row.verdict === "compliant") compliance.compliant++;
    else if (row.verdict === "non_compliant") compliance.nonCompliant++;
    else compliance.unknown++;
    if (row.nextCheckAt && row.nextCheckAt <= now) staleChecks++;
  }

  const recentDenials: ZtnaStats["recentDenials"] = [];
  for (const entry of deniedAudits) {
    if (recentDenials.length >= 5) break;
    const after = parseObject<EvaluateAuditAfter>(entry.afterState);
    if (after.decision !== "deny") continue;
    recentDenials.push({
      at: entry.createdAt.toISOString(),
      user: after.user ?? null,
      deviceId: after.deviceId ?? null,
      appName: after.appName ?? null,
      matchedPolicyId: after.matchedPolicyId ?? null,
      reason: after.reason ?? "",
    });
  }

  return { apps, policies, enabledPolicies, profiles, compliance, staleChecks, recentDenials };
}

// re-export so routes/tests can import the pure engine from one ztna module
export { decideAccess, evaluatePosture, CHECK_KEYS };
export type { AccessPolicyInput, PostureChecks, PostureResults, PostureVerdict, CheckKey };
