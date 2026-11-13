/**
 * URL Filtering service (M16, spec 2.3) — policies, category rules (replace-all
 * upsert), custom allow/block lists (+ paste import), the SIMULATED test
 * decision engine (the appliance/Squid enforces for real) and paged-lite logs
 * + 24h stats. All queries are tenant-scoped; mutations are audited by the
 * route layer which snapshots section `url_filter`.
 */

import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import type { Prisma, UrlCustomList, UrlFilterLog, UrlFilterPolicy } from "@prisma/client";
import {
  ALWAYS_BLOCKED,
  URL_CATEGORIES,
  isSearchEngine,
  lookupCategory,
} from "./catalog";
import { valueMatchesMatchType } from "@/lib/validators/url-filter";

// ── DTOs (mirrored in components/views/url-filter/url-filter-api.ts) ────────

export type PolicyAction = "allow" | "block";
export type RuleAction = "allow" | "block" | "warn";
export type UrlLogAction = "allowed" | "blocked" | "warned";
export type UrlFilterReason =
  | "category"
  | "custom_block"
  | "custom_allow"
  | "safe_search"
  | "file_type"
  | "default";

export interface UrlPolicyDTO {
  id: number;
  name: string;
  defaultAction: PolicyAction;
  safeSearchEnforce: boolean;
  fileTypesBlocked: string[];
  httpsInspection: boolean;
  transparentProxy: boolean;
  enabled: boolean;
  ruleCount: number;
  customListCount: number;
  createdAt: string;
}

export interface CategoryRuleDTO {
  category: string;
  action: RuleAction;
  listSource: "aggregated" | "custom";
  enabled: boolean;
  /** false = implicit row (no stored rule yet — default action applies). */
  configured: boolean;
}

export interface CustomListDTO {
  id: number;
  policyId: number;
  listType: "block" | "allow";
  matchType: "domain" | "wildcard" | "url";
  value: string;
  note: string | null;
  createdAt: string;
}

export interface UrlFilterLogDTO {
  id: number;
  clientIp: string;
  method: string;
  url: string;
  domain: string;
  category: string;
  action: UrlLogAction;
  reason: string;
  policyId: number | null;
  createdAt: string;
}

export interface UrlTestResultDTO {
  decision: UrlLogAction;
  reason: UrlFilterReason;
  category?: string;
}

export interface UrlFilterStatsDTO {
  allowed24h: number;
  blocked24h: number;
  warned24h: number;
  topBlocked: Array<{ domain: string; count: number }>;
  categoryBreakdown: Record<string, number>;
}

export interface ImportResultDTO {
  created: number;
  skipped: number;
}

// ── helpers ─────────────────────────────────────────────────────────────────

const MAX_IMPORT = 500;

/** Parse the JSON string column defensively — bad payload → []. */
function parseFileTypes(json: string): string[] {
  try {
    const parsed: unknown = JSON.parse(json);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((v): v is string => typeof v === "string");
  } catch {
    return [];
  }
}

function toPolicyDTO(
  row: UrlFilterPolicy,
  ruleCount = 0,
  customListCount = 0,
): UrlPolicyDTO {
  return {
    id: row.id,
    name: row.name,
    defaultAction: row.defaultAction as PolicyAction,
    safeSearchEnforce: row.safeSearchEnforce,
    fileTypesBlocked: parseFileTypes(row.fileTypesBlocked),
    httpsInspection: row.httpsInspection,
    transparentProxy: row.transparentProxy,
    enabled: row.enabled,
    ruleCount,
    customListCount,
    createdAt: row.createdAt.toISOString(),
  };
}

function toCustomListDTO(row: UrlCustomList): CustomListDTO {
  return {
    id: row.id,
    policyId: row.policyId,
    listType: row.listType as CustomListDTO["listType"],
    matchType: row.matchType as CustomListDTO["matchType"],
    value: row.value,
    note: row.note,
    createdAt: row.createdAt.toISOString(),
  };
}

function toLogDTO(row: UrlFilterLog): UrlFilterLogDTO {
  return {
    id: row.id,
    clientIp: row.clientIp,
    method: row.method,
    url: row.url,
    domain: row.domain,
    category: row.category,
    action: row.action as UrlLogAction,
    reason: row.reason,
    policyId: row.policyId,
    createdAt: row.createdAt.toISOString(),
  };
}

async function requirePolicy(tenantId: number, policyId: number) {
  const policy = await db.urlFilterPolicy.findFirst({ where: { id: policyId, tenantId } });
  if (!policy) throw ApiError.notFound("URL filter policy not found");
  return policy;
}

/** Lowercase extension of the URL path's last segment, or null. */
function fileExtensionOf(path: string): string | null {
  const last = path.split("/").pop() ?? "";
  const dot = last.lastIndexOf(".");
  if (dot <= 0 || dot === last.length - 1) return null;
  const ext = last.slice(dot + 1).toLowerCase();
  return /^[a-z0-9]{1,10}$/.test(ext) ? ext : null;
}

// ── policies ────────────────────────────────────────────────────────────────

export async function listPolicies(tenantId: number): Promise<UrlPolicyDTO[]> {
  const [rows, ruleCounts, listCounts] = await Promise.all([
    db.urlFilterPolicy.findMany({ where: { tenantId }, orderBy: { id: "asc" } }),
    db.urlCategoryRule.groupBy({ by: ["policyId"], where: { tenantId }, _count: { _all: true } }),
    db.urlCustomList.groupBy({ by: ["policyId"], where: { tenantId }, _count: { _all: true } }),
  ]);
  const ruleMap = new Map(ruleCounts.map((r) => [r.policyId, r._count._all]));
  const listMap = new Map(listCounts.map((r) => [r.policyId, r._count._all]));
  return rows.map((r) => toPolicyDTO(r, ruleMap.get(r.id) ?? 0, listMap.get(r.id) ?? 0));
}

export async function createPolicy(
  tenantId: number,
  input: import("@/lib/validators/url-filter").PolicyCreate,
): Promise<UrlPolicyDTO> {
  const created = await db.urlFilterPolicy.create({
    data: {
      tenantId,
      name: input.name,
      defaultAction: input.defaultAction,
      safeSearchEnforce: input.safeSearchEnforce,
      fileTypesBlocked: JSON.stringify(input.fileTypesBlocked),
      httpsInspection: input.httpsInspection,
      transparentProxy: input.transparentProxy,
      enabled: input.enabled,
    },
  });
  return toPolicyDTO(created);
}

export async function updatePolicy(
  tenantId: number,
  id: number,
  input: import("@/lib/validators/url-filter").PolicyUpdate,
): Promise<UrlPolicyDTO> {
  await requirePolicy(tenantId, id);
  const data: Prisma.UrlFilterPolicyUpdateInput = {};
  if (input.name !== undefined) data.name = input.name;
  if (input.defaultAction !== undefined) data.defaultAction = input.defaultAction;
  if (input.safeSearchEnforce !== undefined) data.safeSearchEnforce = input.safeSearchEnforce;
  if (input.fileTypesBlocked !== undefined) data.fileTypesBlocked = JSON.stringify(input.fileTypesBlocked);
  if (input.httpsInspection !== undefined) data.httpsInspection = input.httpsInspection;
  if (input.transparentProxy !== undefined) data.transparentProxy = input.transparentProxy;
  if (input.enabled !== undefined) data.enabled = input.enabled;
  const updated = await db.urlFilterPolicy.update({ where: { id }, data });
  return toPolicyDTO(updated);
}

export async function deletePolicy(tenantId: number, id: number): Promise<{ ok: true }> {
  await requirePolicy(tenantId, id);
  await db.$transaction([
    db.urlCategoryRule.deleteMany({ where: { tenantId, policyId: id } }),
    db.urlCustomList.deleteMany({ where: { tenantId, policyId: id } }),
    db.urlFilterPolicy.delete({ where: { id } }),
  ]);
  return { ok: true };
}

// ── category rules (joined 13-row view + replace-all) ───────────────────────

export async function listCategoryRules(tenantId: number, policyId: number): Promise<CategoryRuleDTO[]> {
  await requirePolicy(tenantId, policyId);
  const rows = await db.urlCategoryRule.findMany({ where: { tenantId, policyId } });
  const byCat = new Map(rows.map((r) => [r.category, r]));
  return URL_CATEGORIES.map(
    (category): CategoryRuleDTO => {
      const row = byCat.get(category);
      if (!row) return { category, action: "allow", listSource: "aggregated", enabled: false, configured: false };
      return {
        category,
        action: row.action as RuleAction,
        listSource: row.listSource as CategoryRuleDTO["listSource"],
        enabled: row.enabled,
        configured: true,
      };
    },
  );
}

export async function replaceCategoryRules(
  tenantId: number,
  policyId: number,
  rules: import("@/lib/validators/url-filter").CategoryRulesPut["rules"],
): Promise<CategoryRuleDTO[]> {
  await requirePolicy(tenantId, policyId);
  await db.$transaction([
    db.urlCategoryRule.deleteMany({ where: { tenantId, policyId } }),
    db.urlCategoryRule.createMany({
      data: rules.map((r) => ({
        tenantId,
        policyId,
        category: r.category,
        action: r.action,
        listSource: r.listSource,
        enabled: r.enabled,
      })),
    }),
  ]);
  return listCategoryRules(tenantId, policyId);
}

// ── custom lists ────────────────────────────────────────────────────────────

export async function listCustomLists(
  tenantId: number,
  filter: { policyId?: number; listType?: "block" | "allow" },
): Promise<CustomListDTO[]> {
  const rows = await db.urlCustomList.findMany({
    where: {
      tenantId,
      ...(filter.policyId !== undefined ? { policyId: filter.policyId } : {}),
      ...(filter.listType !== undefined ? { listType: filter.listType } : {}),
    },
    orderBy: [{ policyId: "asc" }, { id: "desc" }],
  });
  return rows.map(toCustomListDTO);
}

export async function createCustomList(
  tenantId: number,
  input: import("@/lib/validators/url-filter").CustomListCreate,
): Promise<CustomListDTO> {
  await requirePolicy(tenantId, input.policyId);
  const created = await db.urlCustomList.create({
    data: {
      tenantId,
      policyId: input.policyId,
      listType: input.listType,
      matchType: input.matchType,
      value: input.value.toLowerCase(),
      note: input.note ?? null,
    },
  });
  return toCustomListDTO(created);
}

export async function deleteCustomList(tenantId: number, id: number): Promise<{ ok: true }> {
  const row = await db.urlCustomList.findFirst({ where: { id, tenantId }, select: { id: true } });
  if (!row) throw ApiError.notFound("Custom list entry not found");
  await db.urlCustomList.delete({ where: { id } });
  return { ok: true };
}

/**
 * Import-by-paste — newline-separated values. Skips blanks, `#` comments,
 * invalid values and duplicates (already stored or earlier in the batch);
 * matchType is inferred per line; ≤500 rows created per call.
 */
export async function importCustomLists(
  tenantId: number,
  input: import("@/lib/validators/url-filter").CustomListImport,
): Promise<ImportResultDTO> {
  await requirePolicy(tenantId, input.policyId);

  const existing = await db.urlCustomList.findMany({
    where: { tenantId, policyId: input.policyId, listType: input.listType },
    select: { value: true },
  });
  const seen = new Set(existing.map((r) => r.value));

  const candidates: Array<{ matchType: CustomListDTO["matchType"]; value: string }> = [];
  let skipped = 0;

  for (const rawLine of input.text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line === "" || line.startsWith("#")) {
      skipped += line === "" ? 0 : 1;
      continue;
    }
    if (candidates.length >= MAX_IMPORT) {
      skipped += 1;
      continue;
    }
    const value = line.toLowerCase();
    let matchType: CustomListDTO["matchType"] | null = null;
    if (value.startsWith("http://") || value.startsWith("https://")) matchType = "url";
    else if (value.startsWith("*.")) matchType = "wildcard";
    else if (valueMatchesMatchType("domain", value)) matchType = "domain";
    if (!matchType || seen.has(value)) {
      skipped += 1;
      continue;
    }
    seen.add(value);
    candidates.push({ matchType, value });
  }

  if (candidates.length > 0) {
    await db.urlCustomList.createMany({
      data: candidates.map((c) => ({
        tenantId,
        policyId: input.policyId,
        listType: input.listType,
        matchType: c.matchType,
        value: c.value,
      })),
    });
  }
  return { created: candidates.length, skipped };
}

// ── simulated test (spec 2.3.4 — appliance/Squid enforces for real) ─────────

export async function testUrl(
  tenantId: number,
  policyId: number,
  rawUrl: string,
  clientIp: string,
): Promise<UrlTestResultDTO> {
  const policy = await requirePolicy(tenantId, policyId);
  const [rules, lists] = await Promise.all([
    db.urlCategoryRule.findMany({ where: { tenantId, policyId } }),
    db.urlCustomList.findMany({ where: { tenantId, policyId } }),
  ]);

  const u = new URL(rawUrl);
  const host = u.hostname.toLowerCase();
  const fileTypes = parseFileTypes(policy.fileTypesBlocked);
  const category = lookupCategory(host);

  const inList = (listType: "block" | "allow") =>
    lists.some((l) => l.listType === listType && listValueHit(l.matchType, l.value, host, rawUrl));

  let decision: UrlLogAction;
  let reason: UrlFilterReason;

  if (inList("allow")) {
    decision = "allowed";
    reason = "custom_allow";
  } else if (inList("block")) {
    decision = "blocked";
    reason = "custom_block";
  } else if (category !== null && ALWAYS_BLOCKED.has(category)) {
    decision = "blocked";
    reason = "category";
  } else {
    const rule = category !== null ? rules.find((r) => r.category === category) : undefined;
    const ruleAction = rule && rule.enabled ? (rule.action as RuleAction) : null;
    if (ruleAction === "block") {
      decision = "blocked";
      reason = "category";
    } else if (ruleAction === "warn") {
      decision = "warned";
      reason = "category";
    } else if (policy.safeSearchEnforce && isSearchEngine(host) && u.searchParams.has("q")) {
      decision = "allowed";
      reason = "safe_search";
    } else {
      const ext = fileExtensionOf(u.pathname);
      if (ext !== null && fileTypes.includes(ext)) {
        decision = "blocked";
        reason = "file_type";
      } else {
        decision = policy.defaultAction === "block" ? "blocked" : "allowed";
        reason = "default";
      }
    }
  }

  await db.urlFilterLog.create({
    data: {
      tenantId,
      clientIp,
      method: "GET",
      url: rawUrl,
      domain: host,
      category: category ?? "uncategorized",
      action: decision,
      reason,
      policyId,
    },
  });

  return category !== null ? { decision, reason, category } : { decision, reason };
}

/** Custom-list match semantics: exact/suffix domain, `*.base` wildcard, URL prefix. */
function listValueHit(matchType: string, value: string, host: string, fullUrl: string): boolean {
  if (matchType === "url") return fullUrl.toLowerCase().startsWith(value.toLowerCase());
  if (matchType === "wildcard") {
    const base = value.slice(2);
    return host === base || host.endsWith(`.${base}`);
  }
  return host === value || host.endsWith(`.${value}`);
}

// ── logs (paged-lite) + stats ───────────────────────────────────────────────

export async function listLogs(
  tenantId: number,
  q: import("@/lib/validators/url-filter").UrlFilterLogQuery,
): Promise<{ data: UrlFilterLogDTO[]; meta: { page: number; limit: number; total: number; totalPages: number } }> {
  const where: Prisma.UrlFilterLogWhereInput = {
    tenantId,
    ...(q.action !== undefined ? { action: q.action } : {}),
    ...(q.q
      ? {
          OR: [
            { url: { contains: q.q } },
            { domain: { contains: q.q } },
            { clientIp: { contains: q.q } },
          ],
        }
      : {}),
  };
  const [rows, total] = await Promise.all([
    db.urlFilterLog.findMany({ where, orderBy: { createdAt: "desc" }, take: q.limit }),
    db.urlFilterLog.count({ where }),
  ]);
  return { data: rows.map(toLogDTO), meta: { page: 1, limit: q.limit, total, totalPages: 1 } };
}

export async function getStats(tenantId: number): Promise<UrlFilterStatsDTO> {
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const range = { tenantId, createdAt: { gte: since } };

  const [byAction, topBlockedRows, byCategory] = await Promise.all([
    db.urlFilterLog.groupBy({ by: ["action"], where: range, _count: { _all: true } }),
    db.urlFilterLog.groupBy({
      by: ["domain"],
      where: { ...range, action: "blocked" },
      _count: { _all: true },
      orderBy: { _count: { domain: "desc" } },
      take: 5,
    }),
    db.urlFilterLog.groupBy({ by: ["category"], where: range, _count: { _all: true } }),
  ]);

  const actionCount = (a: string) => byAction.find((r) => r.action === a)?._count._all ?? 0;
  const categoryBreakdown: Record<string, number> = {};
  for (const row of byCategory) categoryBreakdown[row.category] = row._count._all;

  return {
    allowed24h: actionCount("allowed"),
    blocked24h: actionCount("blocked"),
    warned24h: actionCount("warned"),
    topBlocked: topBlockedRows.map((r) => ({ domain: r.domain, count: r._count._all })),
    categoryBreakdown,
  };
}
