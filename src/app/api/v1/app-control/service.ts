/**
 * Application Control service (M18, spec 2.2) — policies, per-app nDPI rules,
 * the SIMULATED test decision engine (the appliance/nDPI enforces for real),
 * paged-lite logs and 24h stats. All queries are tenant-scoped; mutations are
 * audited by the route layer which snapshots section `app_control`.
 */

import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import type { Prisma, AppControlLog, AppControlPolicy, AppControlRule } from "@prisma/client";
import { isKnownApp, categoryOf } from "./catalog";
import type { PolicyAction, RuleAction, UnknownAppAction, Direction, AppLogAction } from "@/lib/validators/app-control";

// ── DTOs (mirrored in components/views/app-control/app-control-api.ts) ──────

export interface AppPolicyDTO {
  id: number;
  name: string;
  defaultAction: PolicyAction;
  unknownAppAction: UnknownAppAction;
  enabled: boolean;
  ruleCount: number;
  createdAt: string;
}

export interface AppRuleDTO {
  id: number;
  policyId: number;
  appName: string;
  category: string;
  action: RuleAction;
  bandwidthLimitMbps: number | null;
  direction: Direction;
  userGroupIds: number[];
  enabled: boolean;
  hitCount: number;
}

export interface AppLogDTO {
  id: number;
  appName: string;
  action: AppLogAction;
  clientIp: string;
  bytes: number;
  ruleId: number | null;
  createdAt: string;
}

export type AppDecision = "allowed" | "blocked" | "limited";
export type AppTestReason = "rule" | "unknown_app" | "default";

export interface AppTestResultDTO {
  decision: AppDecision;
  appName: string;
  ruleId?: number;
  bandwidthLimitMbps?: number;
  reason: AppTestReason;
}

export interface AppStatsDTO {
  allowed24h: number;
  blocked24h: number;
  limited24h: number;
  topApps: Array<{ appName: string; count: number; bytes: number }>;
  ruleHitCounts: Array<{ appName: string; hitCount: number }>;
}

// ── helpers ─────────────────────────────────────────────────────────────────

/** Parse the JSON id-array column defensively — bad payload → []. */
function parseUserGroupIds(json: string): number[] {
  try {
    const parsed: unknown = JSON.parse(json);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((v): v is number => typeof v === "number" && Number.isInteger(v));
  } catch {
    return [];
  }
}

function toPolicyDTO(row: AppControlPolicy, ruleCount = 0): AppPolicyDTO {
  return {
    id: row.id,
    name: row.name,
    defaultAction: row.defaultAction as PolicyAction,
    unknownAppAction: row.unknownAppAction as UnknownAppAction,
    enabled: row.enabled,
    ruleCount,
    createdAt: row.createdAt.toISOString(),
  };
}

function toRuleDTO(row: AppControlRule): AppRuleDTO {
  return {
    id: row.id,
    policyId: row.policyId,
    appName: row.appName,
    category: row.category,
    action: row.action as RuleAction,
    bandwidthLimitMbps: row.bandwidthLimitMbps,
    direction: row.direction as Direction,
    userGroupIds: parseUserGroupIds(row.userGroupIds),
    enabled: row.enabled,
    hitCount: row.hitCount,
  };
}

function toLogDTO(row: AppControlLog): AppLogDTO {
  return {
    id: row.id,
    appName: row.appName,
    action: row.action as AppLogAction,
    clientIp: row.clientIp,
    bytes: row.bytes,
    ruleId: row.ruleId,
    createdAt: row.createdAt.toISOString(),
  };
}

async function requirePolicy(tenantId: number, policyId: number): Promise<AppControlPolicy> {
  const policy = await db.appControlPolicy.findFirst({ where: { id: policyId, tenantId } });
  if (!policy) throw ApiError.notFound("App control policy not found");
  return policy;
}

async function requireRule(tenantId: number, ruleId: number): Promise<AppControlRule> {
  const rule = await db.appControlRule.findFirst({ where: { id: ruleId, tenantId } });
  if (!rule) throw ApiError.notFound("App control rule not found");
  return rule;
}

/** All ids must exist as UserGroups of the tenant — else 400 with fieldErrors. */
async function validateUserGroupIds(tenantId: number, ids: number[]): Promise<void> {
  if (ids.length === 0) return;
  const unique = [...new Set(ids)];
  const found = await db.userGroup.findMany({
    where: { tenantId, id: { in: unique } },
    select: { id: true },
  });
  if (found.length !== unique.length) {
    const foundIds = new Set(found.map((g) => g.id));
    const missing = unique.filter((id) => !foundIds.has(id)).join(", ");
    throw ApiError.validation("Unknown user group id(s)", {
      fieldErrors: { userGroupIds: [`Unknown group id(s) for this tenant: ${missing}`] },
    });
  }
}

/** nDPI label must be in the catalog — else 400 with fieldErrors. */
function requireKnownApp(appName: string): void {
  if (!isKnownApp(appName)) {
    throw ApiError.validation("Unknown application", {
      fieldErrors: { appName: [`'${appName}' is not in the nDPI application catalog`] },
    });
  }
}

/** Deterministic pseudo-random byte volume 10k–500k from the app name hash. */
export function pseudoBytesFor(appName: string): number {
  let h = 0x811c9dc5; // FNV-1a 32-bit offset basis
  for (let i = 0; i < appName.length; i += 1) {
    h ^= appName.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0; // FNV prime
  }
  return 10_000 + (h % 490_001);
}

// ── policies (M18 §2.2.1) ───────────────────────────────────────────────────

export async function listPolicies(tenantId: number): Promise<AppPolicyDTO[]> {
  const [rows, ruleCounts] = await Promise.all([
    db.appControlPolicy.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
    db.appControlRule.groupBy({ by: ["policyId"], where: { tenantId }, _count: { _all: true } }),
  ]);
  const ruleMap = new Map(ruleCounts.map((r) => [r.policyId, r._count._all]));
  return rows.map((r) => toPolicyDTO(r, ruleMap.get(r.id) ?? 0));
}

export async function createPolicy(
  tenantId: number,
  input: import("@/lib/validators/app-control").PolicyCreate,
): Promise<AppPolicyDTO> {
  const created = await db.appControlPolicy.create({
    data: {
      tenantId,
      name: input.name,
      defaultAction: input.defaultAction,
      unknownAppAction: input.unknownAppAction,
      enabled: input.enabled,
    },
  });
  return toPolicyDTO(created);
}

export async function updatePolicy(
  tenantId: number,
  id: number,
  input: import("@/lib/validators/app-control").PolicyUpdate,
): Promise<AppPolicyDTO> {
  await requirePolicy(tenantId, id);
  const data: Prisma.AppControlPolicyUpdateInput = {};
  if (input.name !== undefined) data.name = input.name;
  if (input.defaultAction !== undefined) data.defaultAction = input.defaultAction;
  if (input.unknownAppAction !== undefined) data.unknownAppAction = input.unknownAppAction;
  if (input.enabled !== undefined) data.enabled = input.enabled;
  const updated = await db.appControlPolicy.update({ where: { id }, data });
  const ruleCount = await db.appControlRule.count({ where: { tenantId, policyId: id } });
  return toPolicyDTO(updated, ruleCount);
}

export async function deletePolicy(tenantId: number, id: number): Promise<{ ok: true }> {
  await requirePolicy(tenantId, id);
  const rules = await db.appControlRule.findMany({
    where: { tenantId, policyId: id },
    select: { appName: true },
    orderBy: { appName: "asc" },
    take: 8,
  });
  if (rules.length > 0) {
    throw ApiError.conflict("Policy still has application rules — remove them first", {
      referencedBy: rules.map((r) => ({ ruleName: r.appName, ruleType: "app_control" })),
    });
  }
  await db.appControlPolicy.delete({ where: { id } });
  return { ok: true };
}

// ── rules (M18 §2.2.2) ──────────────────────────────────────────────────────

export async function listRules(tenantId: number, policyId: number): Promise<AppRuleDTO[]> {
  await requirePolicy(tenantId, policyId);
  const rows = await db.appControlRule.findMany({
    where: { tenantId, policyId },
    orderBy: [{ id: "asc" }],
  });
  return rows.map(toRuleDTO);
}

export async function createRule(
  tenantId: number,
  policyId: number,
  input: import("@/lib/validators/app-control").RuleCreate,
): Promise<AppRuleDTO> {
  await requirePolicy(tenantId, policyId);
  requireKnownApp(input.appName);
  await validateUserGroupIds(tenantId, input.userGroupIds);
  const category = input.category ?? categoryOf(input.appName) ?? "media";
  const created = await db.appControlRule.create({
    data: {
      tenantId,
      policyId,
      appName: input.appName,
      category,
      action: input.action,
      bandwidthLimitMbps: input.action === "limit" ? (input.bandwidthLimitMbps ?? null) : null,
      direction: input.direction,
      userGroupIds: JSON.stringify(input.userGroupIds),
      enabled: input.enabled,
    },
  });
  return toRuleDTO(created);
}

export async function updateRule(
  tenantId: number,
  ruleId: number,
  input: import("@/lib/validators/app-control").RuleUpdate,
): Promise<AppRuleDTO> {
  const existing = await requireRule(tenantId, ruleId);
  if (input.appName !== undefined) requireKnownApp(input.appName);
  if (input.userGroupIds !== undefined) await validateUserGroupIds(tenantId, input.userGroupIds);

  const data: Prisma.AppControlRuleUpdateInput = {};
  if (input.appName !== undefined) data.appName = input.appName;
  if (input.category !== undefined) data.category = input.category;
  if (input.direction !== undefined) data.direction = input.direction;
  if (input.userGroupIds !== undefined) data.userGroupIds = JSON.stringify(input.userGroupIds);
  if (input.enabled !== undefined) data.enabled = input.enabled;

  const finalAction = (input.action ?? existing.action) as RuleAction;
  if (input.action !== undefined) data.action = input.action;
  if (finalAction === "limit") {
    // keep the stored limit when the caller only flips the action inline
    data.bandwidthLimitMbps = input.bandwidthLimitMbps ?? existing.bandwidthLimitMbps ?? 10;
  } else {
    data.bandwidthLimitMbps = null;
  }

  const updated = await db.appControlRule.update({ where: { id: ruleId }, data });
  return toRuleDTO(updated);
}

export async function deleteRule(tenantId: number, ruleId: number): Promise<{ ok: true }> {
  await requireRule(tenantId, ruleId);
  await db.appControlRule.delete({ where: { id: ruleId } });
  return { ok: true };
}

// ── simulated test (M18 §2.2.4 — appliance/nDPI enforces for real) ──────────

/**
 * Resolve the decision for one app against one policy:
 *  1. enabled rule for appName → its action (limit → limited + Mbps), reason "rule"
 *  2. app not in the nDPI catalog → policy.unknownAppAction ("log" passes but logs), reason "unknown_app"
 *  3. known app without a rule → policy.defaultAction, reason "default"
 * Persists an AppControlLog row (deterministic bytes) and bumps rule.hitCount.
 */
export async function testApp(
  tenantId: number,
  policyId: number,
  input: import("@/lib/validators/app-control").AppTestInput,
  fallbackClientIp: string,
): Promise<AppTestResultDTO> {
  const policy = await requirePolicy(tenantId, policyId);

  const rule = await db.appControlRule.findFirst({
    where: { tenantId, policyId, appName: input.appName, enabled: true },
  });

  let decision: AppDecision;
  let reason: AppTestReason;
  let bandwidthLimitMbps: number | undefined;
  let ruleId: number | undefined;

  if (rule) {
    const action = rule.action as RuleAction;
    if (action === "limit") {
      decision = "limited";
      bandwidthLimitMbps = rule.bandwidthLimitMbps ?? 10;
    } else {
      decision = action === "block" ? "blocked" : "allowed";
    }
    reason = "rule";
    ruleId = rule.id;
    await db.appControlRule.update({ where: { id: rule.id }, data: { hitCount: { increment: 1 } } });
  } else if (!isKnownApp(input.appName)) {
    decision =
      policy.unknownAppAction === "block" ? "blocked" : "allowed"; // "log" passes + logs
    reason = "unknown_app";
  } else {
    decision = (policy.defaultAction as PolicyAction) === "block" ? "blocked" : "allowed";
    reason = "default";
  }

  await db.appControlLog.create({
    data: {
      tenantId,
      appName: input.appName,
      action: decision,
      clientIp: input.clientIp?.trim() || fallbackClientIp,
      bytes: pseudoBytesFor(input.appName),
      ruleId: ruleId ?? null,
    },
  });

  return bandwidthLimitMbps !== undefined
    ? { decision, appName: input.appName, reason, ...(ruleId !== undefined ? { ruleId } : {}), bandwidthLimitMbps }
    : { decision, appName: input.appName, reason, ...(ruleId !== undefined ? { ruleId } : {}) };
}

// ── logs (paged-lite) + stats (M18 §2.2.5/§2.2.6) ───────────────────────────

export async function listLogs(
  tenantId: number,
  q: import("@/lib/validators/app-control").AppControlLogQuery,
): Promise<{ data: AppLogDTO[]; meta: { page: number; limit: number; total: number; totalPages: number } }> {
  const where: Prisma.AppControlLogWhereInput = {
    tenantId,
    ...(q.appName !== undefined ? { appName: q.appName } : {}),
    ...(q.action !== undefined ? { action: q.action } : {}),
  };
  const [rows, total] = await Promise.all([
    db.appControlLog.findMany({ where, orderBy: { createdAt: "desc" }, take: q.limit }),
    db.appControlLog.count({ where }),
  ]);
  return { data: rows.map(toLogDTO), meta: { page: 1, limit: q.limit, total, totalPages: 1 } };
}

export async function getStats(tenantId: number): Promise<AppStatsDTO> {
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const range = { tenantId, createdAt: { gte: since } };

  const [byAction, topAppRows, rules] = await Promise.all([
    db.appControlLog.groupBy({ by: ["action"], where: range, _count: { _all: true } }),
    db.appControlLog.groupBy({
      by: ["appName"],
      where: range,
      _count: { _all: true },
      _sum: { bytes: true },
      orderBy: { _count: { appName: "desc" } },
      take: 5,
    }),
    db.appControlRule.findMany({
      where: { tenantId },
      select: { appName: true, hitCount: true },
      orderBy: { hitCount: "desc" },
    }),
  ]);

  const actionCount = (a: string) => byAction.find((r) => r.action === a)?._count._all ?? 0;

  return {
    allowed24h: actionCount("allowed"),
    blocked24h: actionCount("blocked"),
    limited24h: actionCount("limited"),
    topApps: topAppRows.map((r) => ({ appName: r.appName, count: r._count._all, bytes: r._sum.bytes ?? 0 })),
    ruleHitCounts: rules.map((r) => ({ appName: r.appName, hitCount: r.hitCount })),
  };
}
