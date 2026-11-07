/**
 * Threat Intelligence service (M13 §2.11) — feeds CRUD, the IOC store,
 * auto-block rules and hit/stats queries over the M13 tables. The simulated
 * ingestion engine (sync) lives in corpus.ts; this module only reads/writes
 * config + observation rows. SQLite has no Prisma relation on the logical
 * refs (Ioc.feedId, AutoBlockRule.iocId, IocHit.iocId), so joins are done
 * with explicit findMany maps.
 */

import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import type { PageMeta } from "@/lib/api/envelope";
import { reputationFor } from "./corpus";
import type {
  AutoBlockCreate,
  AutoBlockUpdate,
  FeedCreate,
  FeedUpdate,
  HitsQuery,
  IocCreate,
  IocQuery,
  ThreatSeverity,
} from "@/lib/validators/threat-intel";

// ── DTOs ────────────────────────────────────────────────────────────────────

export type FeedDTO = {
  id: number;
  name: string;
  provider: string; // abusech | otx | spamhaus | custom
  url: string;
  format: string; // csv | json | stix | taxii
  category: string;
  intervalMinutes: number;
  autoBlock: boolean;
  enabled: boolean;
  lastSyncAt: string | null;
  lastStatus: string; // ok | error | never
  lastCount: number;
};

export type IocDTO = {
  id: number;
  feedId: number | null;
  type: string; // ip | cidr | domain | url | hash
  value: string;
  category: string;
  severity: string; // info | warning | critical
  confidence: number; // 0-100
  reputation: number; // 0-100 (100 = benign)
  source: string; // manual | feed:<name>
  description: string | null;
  hits: number;
  enabled: boolean;
  firstSeen: string;
  lastSeen: string;
  expiresAt: string | null;
};

export type AutoBlockRuleDTO = {
  id: number;
  name: string;
  iocId: number | null;
  matchType: string;
  matchValue: string;
  action: string; // drop | reject | quarantine_vlan
  direction: string; // in | out | both
  source: string; // manual | auto-feed
  hitCount: number;
  enabled: boolean;
  createdBy: string;
  createdAt: string;
};

export type IocHitDTO = {
  id: number;
  ioc: { id: number; value: string; type: string; severity: string };
  sourceIp: string;
  destIp: string | null;
  action: string; // allowed | blocked | quarantined
  createdAt: string;
};

export type ThreatStats = {
  totalIocs: number;
  bySeverity: { info: number; warning: number; critical: number };
  byCategory: Record<string, number>;
  activeFeeds: number;
  autoBlockRules: number;
  hits24h: number;
};

// ── mappers ─────────────────────────────────────────────────────────────────

const iso = (d: Date | null): string | null => (d ? d.toISOString() : null);

function toFeedDTO(row: {
  id: number;
  name: string;
  provider: string;
  url: string;
  format: string;
  category: string;
  intervalMinutes: number;
  autoBlock: boolean;
  enabled: boolean;
  lastSyncAt: Date | null;
  lastStatus: string;
  lastCount: number;
}): FeedDTO {
  return {
    id: row.id,
    name: row.name,
    provider: row.provider,
    url: row.url,
    format: row.format,
    category: row.category,
    intervalMinutes: row.intervalMinutes,
    autoBlock: row.autoBlock,
    enabled: row.enabled,
    lastSyncAt: iso(row.lastSyncAt),
    lastStatus: row.lastStatus,
    lastCount: row.lastCount,
  };
}

function toIocDTO(row: {
  id: number;
  feedId: number | null;
  type: string;
  value: string;
  category: string;
  severity: string;
  confidence: number;
  reputation: number;
  source: string;
  description: string | null;
  hits: number;
  enabled: boolean;
  firstSeen: Date;
  lastSeen: Date;
  expiresAt: Date | null;
}): IocDTO {
  return {
    id: row.id,
    feedId: row.feedId,
    type: row.type,
    value: row.value,
    category: row.category,
    severity: row.severity,
    confidence: row.confidence,
    reputation: row.reputation,
    source: row.source,
    description: row.description,
    hits: row.hits,
    enabled: row.enabled,
    firstSeen: row.firstSeen.toISOString(),
    lastSeen: row.lastSeen.toISOString(),
    expiresAt: iso(row.expiresAt),
  };
}

function toAutoBlockRuleDTO(row: {
  id: number;
  name: string;
  iocId: number | null;
  matchType: string;
  matchValue: string;
  action: string;
  direction: string;
  source: string;
  hitCount: number;
  enabled: boolean;
  createdBy: string;
  createdAt: Date;
}): AutoBlockRuleDTO {
  return {
    id: row.id,
    name: row.name,
    iocId: row.iocId,
    matchType: row.matchType,
    matchValue: row.matchValue,
    action: row.action,
    direction: row.direction,
    source: row.source,
    hitCount: row.hitCount,
    enabled: row.enabled,
    createdBy: row.createdBy,
    createdAt: row.createdAt.toISOString(),
  };
}

// ── feeds (M13 §2.11 tab 1) ─────────────────────────────────────────────────

export async function listFeeds(tenantId: number): Promise<FeedDTO[]> {
  const rows = await db.threatFeed.findMany({ where: { tenantId }, orderBy: { id: "asc" } });
  return rows.map(toFeedDTO);
}

export async function createFeed(tenantId: number, body: FeedCreate): Promise<FeedDTO> {
  const dup = await db.threatFeed.findFirst({ where: { tenantId, name: body.name } });
  if (dup) throw ApiError.conflict(`A feed named "${body.name}" already exists`);
  const row = await db.threatFeed.create({ data: { tenantId, ...body } });
  return toFeedDTO(row);
}

export async function updateFeed(tenantId: number, id: number, body: FeedUpdate): Promise<FeedDTO> {
  const existing = await db.threatFeed.findFirst({ where: { id, tenantId } });
  if (!existing) throw ApiError.notFound("Threat feed not found");
  if (body.name !== undefined && body.name !== existing.name) {
    const dup = await db.threatFeed.findFirst({ where: { tenantId, name: body.name } });
    if (dup) throw ApiError.conflict(`A feed named "${body.name}" already exists`);
  }
  const row = await db.threatFeed.update({ where: { id: existing.id }, data: body });
  return toFeedDTO(row);
}

export async function deleteFeed(tenantId: number, id: number): Promise<{ ok: true }> {
  const existing = await db.threatFeed.findFirst({ where: { id, tenantId } });
  if (!existing) throw ApiError.notFound("Threat feed not found");
  // IOCs keep their logical feedId (historical provenance) — engine reconciles.
  await db.threatFeed.delete({ where: { id: existing.id } });
  return { ok: true };
}

// ── IOCs (M13 §2.11 tab 2) ──────────────────────────────────────────────────

export async function listIocs(
  tenantId: number,
  query: IocQuery,
): Promise<{ data: IocDTO[]; meta: PageMeta }> {
  const where = {
    tenantId,
    ...(query.severity ? { severity: query.severity } : {}),
    ...(query.category ? { category: query.category } : {}),
    ...(query.type ? { type: query.type } : {}),
    ...(query.feedId ? { feedId: query.feedId } : {}),
    ...(query.q
      ? {
          OR: [
            { value: { contains: query.q } },
            { description: { contains: query.q } },
            { source: { contains: query.q } },
          ],
        }
      : {}),
  };
  const [rows, total] = await Promise.all([
    db.ioc.findMany({
      where,
      orderBy: { lastSeen: "desc" },
      skip: (query.page - 1) * query.limit,
      take: query.limit,
    }),
    db.ioc.count({ where }),
  ]);
  return {
    data: rows.map(toIocDTO),
    meta: { page: query.page, limit: query.limit, total, totalPages: Math.max(1, Math.ceil(total / query.limit)) },
  };
}

export async function createIoc(tenantId: number, body: IocCreate): Promise<IocDTO> {
  const dup = await db.ioc.findUnique({
    where: { tenantId_type_value: { tenantId, type: body.type, value: body.value } },
  });
  if (dup) throw ApiError.conflict(`IOC ${body.type}:${body.value} already exists`);
  const now = new Date();
  const row = await db.ioc.create({
    data: {
      tenantId,
      feedId: null,
      type: body.type,
      value: body.value,
      category: body.category,
      severity: body.severity,
      confidence: body.confidence,
      reputation: reputationFor(body.severity),
      source: "manual",
      description: body.description ?? null,
      expiresAt: body.expiresAt ? new Date(body.expiresAt) : null,
      lastSeen: now,
    },
  });
  return toIocDTO(row);
}

export async function deleteIoc(tenantId: number, id: number): Promise<{ ok: true }> {
  const existing = await db.ioc.findFirst({ where: { id, tenantId } });
  if (!existing) throw ApiError.notFound("IOC not found");
  await db.ioc.delete({ where: { id: existing.id } });
  return { ok: true };
}

/**
 * Soft-disable / re-enable — keeps provenance + hit history, drops the IOC
 * from matching while disabled. Spec path is /disable (default false); the
 * console switch sends { enabled: true } to restore.
 */
export async function disableIoc(tenantId: number, id: number, enabled = false): Promise<IocDTO> {
  const existing = await db.ioc.findFirst({ where: { id, tenantId } });
  if (!existing) throw ApiError.notFound("IOC not found");
  const row = await db.ioc.update({ where: { id: existing.id }, data: { enabled } });
  return toIocDTO(row);
}

// ── auto-block rules (M13 §2.11 tab 3) ──────────────────────────────────────

export async function listAutoBlockRules(tenantId: number): Promise<AutoBlockRuleDTO[]> {
  const rows = await db.autoBlockRule.findMany({ where: { tenantId }, orderBy: { id: "asc" } });
  return rows.map(toAutoBlockRuleDTO);
}

export async function createAutoBlockRule(
  tenantId: number,
  body: AutoBlockCreate,
  createdBy: string,
): Promise<AutoBlockRuleDTO> {
  const dup = await db.autoBlockRule.findUnique({
    where: { tenantId_matchType_matchValue: { tenantId, matchType: body.matchType, matchValue: body.matchValue } },
  });
  if (dup) throw ApiError.conflict(`A rule for ${body.matchType}:${body.matchValue} already exists`);
  const row = await db.autoBlockRule.create({
    data: {
      tenantId,
      name: body.name,
      iocId: body.iocId ?? null,
      matchType: body.matchType,
      matchValue: body.matchValue,
      action: body.action,
      direction: body.direction,
      source: "manual",
      enabled: body.enabled,
      createdBy,
    },
  });
  return toAutoBlockRuleDTO(row);
}

export async function updateAutoBlockRule(
  tenantId: number,
  id: number,
  body: AutoBlockUpdate,
): Promise<AutoBlockRuleDTO> {
  const existing = await db.autoBlockRule.findFirst({ where: { id, tenantId } });
  if (!existing) throw ApiError.notFound("Auto-block rule not found");
  if (
    (body.matchType !== undefined && body.matchType !== existing.matchType) ||
    (body.matchValue !== undefined && body.matchValue !== existing.matchValue)
  ) {
    const matchType = body.matchType ?? existing.matchType;
    const matchValue = body.matchValue ?? existing.matchValue;
    const dup = await db.autoBlockRule.findUnique({
      where: { tenantId_matchType_matchValue: { tenantId, matchType, matchValue } },
    });
    if (dup && dup.id !== existing.id) {
      throw ApiError.conflict(`A rule for ${matchType}:${matchValue} already exists`);
    }
  }
  const row = await db.autoBlockRule.update({ where: { id: existing.id }, data: body });
  return toAutoBlockRuleDTO(row);
}

export async function deleteAutoBlockRule(tenantId: number, id: number): Promise<{ ok: true }> {
  const existing = await db.autoBlockRule.findFirst({ where: { id, tenantId } });
  if (!existing) throw ApiError.notFound("Auto-block rule not found");
  await db.autoBlockRule.delete({ where: { id: existing.id } });
  return { ok: true };
}

// ── hits (recent IOC matches — joined view) ─────────────────────────────────

export async function listHits(tenantId: number, query: HitsQuery): Promise<IocHitDTO[]> {
  const hits = await db.iocHit.findMany({
    where: {
      tenantId,
      ...(query.since ? { createdAt: { gte: new Date(query.since) } } : {}),
    },
    orderBy: { createdAt: "desc" },
    take: query.limit,
  });
  const iocIds = [...new Set(hits.map((h) => h.iocId))];
  const iocs = iocIds.length
    ? await db.ioc.findMany({
        where: { id: { in: iocIds } },
        select: { id: true, value: true, type: true, severity: true },
      })
    : [];
  const byId = new Map(iocs.map((i) => [i.id, i]));
  return hits.map((h) => ({
    id: h.id,
    ioc: byId.get(h.iocId) ?? { id: h.iocId, value: "(deleted)", type: "ip", severity: "info" as ThreatSeverity },
    sourceIp: h.sourceIp,
    destIp: h.destIp,
    action: h.action,
    createdAt: h.createdAt.toISOString(),
  }));
}

// ── stats (console strip + dashboards) ──────────────────────────────────────

export async function getStats(tenantId: number): Promise<ThreatStats> {
  const since = new Date(Date.now() - 24 * 3600_000);
  const [totalIocs, severityGroups, categoryGroups, activeFeeds, autoBlockRules, hits24h] =
    await Promise.all([
      db.ioc.count({ where: { tenantId } }),
      db.ioc.groupBy({ by: ["severity"], where: { tenantId }, _count: { _all: true } }),
      db.ioc.groupBy({ by: ["category"], where: { tenantId }, _count: { _all: true } }),
      db.threatFeed.count({ where: { tenantId, enabled: true } }),
      db.autoBlockRule.count({ where: { tenantId } }),
      db.iocHit.count({ where: { tenantId, createdAt: { gte: since } } }),
    ]);

  const bySeverity: ThreatStats["bySeverity"] = { info: 0, warning: 0, critical: 0 };
  for (const g of severityGroups) {
    if (g.severity === "info" || g.severity === "warning" || g.severity === "critical") {
      bySeverity[g.severity] = g._count._all;
    }
  }
  const byCategory: Record<string, number> = {};
  for (const g of categoryGroups) byCategory[g.category] = g._count._all;

  return { totalIocs, bySeverity, byCategory, activeFeeds, autoBlockRules, hits24h };
}
