/**
 * DNS tunnel-detection service (Phase 3 §3.4) — DB-backed half of the module.
 * Detection input is the DNS query-log source behind /api/v1/dns/query-logs:
 * that route serves the ENGINE RING BUFFER (DnsQueryLogEntry — derived view,
 * not a Prisma model), so runDetection reads getEngine().dnsRing rows inside
 * the lookback. Findings persist to DnsTunnelFinding (dns_tunnel_findings).
 *
 * Upsert contract (spec): same tenant + clientIp + windowStart + verdict
 * → metrics/detail updated in place, never duplicated. A verdict escalation
 * (suspicious → likely_tunnel) intentionally produces a separate row — the
 * dedupe key includes the verdict. Clean windows are never persisted.
 *
 * Empty data is reported honestly ({findings: 0, reason}) — no synthetic rows.
 */

import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { parseJson, stringifyJson } from "@/lib/json";
import {
  aggregateWindows,
  longestLabels,
  topDomains,
  type ClientWindowStat,
  type LabelHit,
  type DomainCount,
  type TunnelQueryInput,
} from "./tunnel-detect";
import type { TunnelFindingStatus, TunnelFindingsQuery, TunnelRunOptions } from "@/lib/validators/dns-tunnel";

// ── DTOs ────────────────────────────────────────────────────────────────────

export interface DnsTunnelFindingDetail {
  topDomains: DomainCount[];
  longestLabels: LabelHit[];
}

export type DnsTunnelFindingDTO = {
  id: number;
  clientIp: string;
  windowStart: string;
  windowEnd: string;
  queryCount: number;
  uniqueDomains: number;
  maxLabelLength: number;
  entropyScore: number;
  verdict: string;
  status: string;
  detail: DnsTunnelFindingDetail;
  createdAt: string;
};

export type DnsTunnelStats = {
  openTotal: number;
  openByVerdict: { suspicious: number; likely_tunnel: number };
  total: number;
  resolvedTotal: number;
  created7d: number;
};

export type RunDetectionResult = {
  findings: number;
  created: number;
  updated: number;
  windowsScanned: number;
  queriesScanned: number;
  windowMinutes: number;
  stepMinutes: number;
  lookbackMinutes: number;
  /** present only when there was nothing to analyze — honest empty result */
  reason?: "no dns query data in window";
};

export interface RunDetectionInput extends Omit<TunnelRunOptions, "windowMinutes" | "stepMinutes" | "lookbackMinutes"> {
  windowMinutes?: number;
  stepMinutes?: number;
  lookbackMinutes?: number;
  tenantId?: number;
  /**
   * Test/batch seam: rows already in scope are used verbatim (bypasses the
   * engine ring + lookback filter). Production routes never set this — the
   * engine ring in the lookback window is the source of truth.
   */
  queries?: TunnelQueryInput[];
}

const DEFAULTS = { windowMinutes: 15, stepMinutes: 5, lookbackMinutes: 60 } as const;

// ── helpers ─────────────────────────────────────────────────────────────────

function normalizeDetail(raw: string): DnsTunnelFindingDetail {
  const parsed = parseJson<Partial<DnsTunnelFindingDetail>>(raw, {});
  const topDomains = Array.isArray(parsed.topDomains)
    ? parsed.topDomains.filter((d) => d && typeof d.domain === "string" && typeof d.count === "number")
    : [];
  const longestLabels = Array.isArray(parsed.longestLabels)
    ? parsed.longestLabels.filter(
        (l) => l && typeof l.label === "string" && typeof l.domain === "string" && typeof l.length === "number",
      )
    : [];
  return { topDomains, longestLabels };
}

function toFindingDTO(row: {
  id: number;
  clientIp: string;
  windowStart: Date;
  windowEnd: Date;
  queryCount: number;
  uniqueDomains: number;
  maxLabelLength: number;
  entropyScore: number;
  verdict: string;
  status: string;
  detail: string;
  createdAt: Date;
}): DnsTunnelFindingDTO {
  return {
    id: row.id,
    clientIp: row.clientIp,
    windowStart: row.windowStart.toISOString(),
    windowEnd: row.windowEnd.toISOString(),
    queryCount: row.queryCount,
    uniqueDomains: row.uniqueDomains,
    maxLabelLength: row.maxLabelLength,
    entropyScore: row.entropyScore,
    verdict: row.verdict,
    status: row.status,
    detail: normalizeDetail(row.detail),
    createdAt: row.createdAt.toISOString(),
  };
}

/** Engine ring rows (all data-plane modes) inside the lookback, in the pure
 *  engine's input shape. Lazy import — keeps test harnesses engine-free. */
async function engineRowsInLookback(lookbackMinutes: number): Promise<TunnelQueryInput[]> {
  const { getEngine } = await import("@/lib/engine");
  const ring = getEngine().dnsRing;
  const sinceMs = Date.now() - lookbackMinutes * 60_000;
  const rows: TunnelQueryInput[] = [];
  for (const r of ring) {
    const t = Date.parse(r.ts);
    if (!Number.isFinite(t) || t < sinceMs) continue;
    rows.push({ clientIp: r.clientIp, domain: r.domain, ts: r.ts });
  }
  return rows;
}

const DETAIL_LIMITS = { topDomains: 5, longestLabels: 5 } as const;

function detailFor(rows: TunnelQueryInput[]): string {
  return stringifyJson({
    topDomains: topDomains(rows, DETAIL_LIMITS.topDomains),
    longestLabels: longestLabels(rows, DETAIL_LIMITS.longestLabels),
  });
}

// ── run detection ───────────────────────────────────────────────────────────

/**
 * One detection pass: load query rows → aggregateWindows → persist every
 * suspicious/likely_tunnel client-window as a DnsTunnelFinding (dedupe per
 * client+window+verdict). Returns honest counters; with no rows in scope it
 * returns {findings: 0, reason: "no dns query data in window"} and writes
 * nothing.
 */
export async function runDetection(opts: RunDetectionInput = {}): Promise<RunDetectionResult> {
  const windowMinutes = opts.windowMinutes ?? DEFAULTS.windowMinutes;
  const stepMinutes = opts.stepMinutes ?? DEFAULTS.stepMinutes;
  const lookbackMinutes = opts.lookbackMinutes ?? DEFAULTS.lookbackMinutes;
  const tenantId = opts.tenantId ?? 1;

  const rows = opts.queries ?? (await engineRowsInLookback(lookbackMinutes));
  const result: RunDetectionResult = {
    findings: 0,
    created: 0,
    updated: 0,
    windowsScanned: 0,
    queriesScanned: rows.length,
    windowMinutes,
    stepMinutes,
    lookbackMinutes,
  };
  if (rows.length === 0) {
    result.reason = "no dns query data in window";
    return result;
  }

  const windows = aggregateWindows(rows, windowMinutes, stepMinutes);
  result.windowsScanned = windows.length;

  for (const win of windows) {
    for (const stat of win.clients) {
      if (stat.verdict === "clean") continue; // findings table is suspicious|likely_tunnel only
      const clientRows = rows.filter((r) => r.clientIp === stat.clientIp && inWindow(r, win));
      const detail = detailFor(clientRows);
      const existing = await db.dnsTunnelFinding.findFirst({
        where: { tenantId, clientIp: stat.clientIp, windowStart: win.windowStart, verdict: stat.verdict },
      });
      if (existing) {
        await db.dnsTunnelFinding.update({
          where: { id: existing.id },
          data: {
            windowEnd: win.windowEnd,
            queryCount: stat.queryCount,
            uniqueDomains: stat.uniqueDomains,
            maxLabelLength: stat.maxLabelLength,
            entropyScore: stat.avgDomainEntropy,
            detail,
          },
        });
        result.updated += 1;
      } else {
        await db.dnsTunnelFinding.create({
          data: {
            tenantId,
            clientIp: stat.clientIp,
            windowStart: win.windowStart,
            windowEnd: win.windowEnd,
            queryCount: stat.queryCount,
            uniqueDomains: stat.uniqueDomains,
            maxLabelLength: stat.maxLabelLength,
            entropyScore: stat.avgDomainEntropy,
            verdict: stat.verdict,
            status: "open",
            detail,
          },
        });
        result.created += 1;
      }
    }
  }

  result.findings = result.created + result.updated;
  return result;
}

function inWindow(row: TunnelQueryInput, win: { windowStart: Date; windowEnd: Date }): boolean {
  if (row.ts === undefined) return true;
  const t = Date.parse(row.ts);
  if (!Number.isFinite(t)) return true;
  return t >= win.windowStart.getTime() && t < win.windowEnd.getTime();
}

/** Pure-engine stats for one window's client rows (exported for callers that
 *  want the analysis without persistence). */
export function analyzeWindowStats(queries: TunnelQueryInput[], windowMinutes: number, stepMinutes: number): ClientWindowStat[] {
  return aggregateWindows(queries, windowMinutes, stepMinutes).flatMap((w) => w.clients);
}

// ── findings CRUD-ish ───────────────────────────────────────────────────────

export async function listFindings(
  tenantId: number,
  filters: Partial<TunnelFindingsQuery> = {},
): Promise<{ data: DnsTunnelFindingDTO[]; meta: { page: number; limit: number; total: number; totalPages: number } }> {
  const page = filters.page ?? 1;
  const limit = filters.limit ?? 50;
  const where = {
    tenantId,
    ...(filters.status ? { status: filters.status } : {}),
    ...(filters.verdict ? { verdict: filters.verdict } : {}),
    ...(filters.q ? { clientIp: { contains: filters.q } } : {}),
  };
  const [total, rows] = await Promise.all([
    db.dnsTunnelFinding.count({ where }),
    db.dnsTunnelFinding.findMany({
      where,
      orderBy: [{ windowStart: "desc" }, { id: "desc" }],
      skip: (page - 1) * limit,
      take: limit,
    }),
  ]);
  return {
    data: rows.map(toFindingDTO),
    meta: { page, limit, total, totalPages: Math.max(1, Math.ceil(total / limit)) },
  };
}

const STATUSES: readonly TunnelFindingStatus[] = ["open", "acknowledged", "resolved"] as const;

export async function updateFindingStatus(tenantId: number, id: number, status: string): Promise<DnsTunnelFindingDTO> {
  if (!STATUSES.includes(status as TunnelFindingStatus)) {
    throw ApiError.validation(`status must be one of ${STATUSES.join(" | ")}`);
  }
  const existing = await db.dnsTunnelFinding.findFirst({ where: { id, tenantId } });
  if (!existing) throw ApiError.notFound("Tunnel finding not found");
  const row = await db.dnsTunnelFinding.update({ where: { id: existing.id }, data: { status } });
  return toFindingDTO(row);
}

// ── stats (console strip) ───────────────────────────────────────────────────

export async function statsFindings(tenantId: number): Promise<DnsTunnelStats> {
  const since7d = new Date(Date.now() - 7 * 24 * 3600_000);
  const [openGroups, total, openTotal, resolvedTotal, created7d] = await Promise.all([
    db.dnsTunnelFinding.groupBy({ by: ["verdict"], where: { tenantId, status: "open" }, _count: { _all: true } }),
    db.dnsTunnelFinding.count({ where: { tenantId } }),
    db.dnsTunnelFinding.count({ where: { tenantId, status: "open" } }),
    db.dnsTunnelFinding.count({ where: { tenantId, status: "resolved" } }),
    db.dnsTunnelFinding.count({ where: { tenantId, createdAt: { gte: since7d } } }),
  ]);
  const openByVerdict: DnsTunnelStats["openByVerdict"] = { suspicious: 0, likely_tunnel: 0 };
  for (const g of openGroups) {
    if (g.verdict === "suspicious" || g.verdict === "likely_tunnel") openByVerdict[g.verdict] = g._count._all;
  }
  return { openTotal, openByVerdict, total, resolvedTotal, created7d };
}
