/**
 * Logs service (M09 §2/§5) — read-only queries over the MockEngine-owned
 * `firewall_logs` / `ips_events` tables (this module never writes them),
 * the append-only audit trail, and CRUD passthroughs for forwarding targets
 * + scheduled reports (config tables, mutated via the handler's audit/snapshot).
 * SQLite JSON columns are parsed with lib/json helpers (ADR-005).
 */

import { db } from "@/lib/db";
import { ApiError } from "@/lib/api/errors";
import { parseJson } from "@/lib/json";
import type { PageMeta } from "@/lib/api/envelope";
import type {
  AuditLogQuery,
  FirewallExportQuery,
  FirewallLogQuery,
  IpsLogQuery,
  NetflowTargetCreate,
  NetflowTargetUpdate,
  ReportScheduleCreate,
  ReportScheduleUpdate,
  StatsRange,
  SyslogTargetCreate,
  SyslogTargetUpdate,
} from "@/lib/validators/logs";

// ── DTOs ────────────────────────────────────────────────────────────────────

export type FirewallLogDTO = {
  id: number;
  timestamp: string;
  srcIp: string | null;
  srcPort: number | null;
  dstIp: string | null;
  dstPort: number | null;
  protocol: string | null;
  action: string | null;
  ruleName: string | null;
  appName: string | null;
  bytes: number;
  packets: number;
  userName: string | null;
};

export type IpsEventDTO = {
  id: number;
  timestamp: string;
  srcIp: string | null;
  srcPort: number | null;
  dstIp: string | null;
  dstPort: number | null;
  action: string; // alert | drop | reject | bypass | suppressed
  sid: string | null;
  severity: string; // info | low | medium | high | critical
  category: string | null;
  message: string | null;
  suppressedUntil: string | null;
};

export type AuditLogDTO = {
  id: number;
  createdAt: string;
  userId: number | null;
  username: string | null;
  sourceIp: string | null;
  action: string;
  objectType: string;
  objectId: number | null;
  objectName: string | null;
  beforeState: string | null; // raw JSON strings — viewer parses defensively
  afterState: string | null;
  result: string; // success | failure | denied
};

export type SyslogTargetDTO = {
  id: number;
  name: string;
  host: string;
  port: number;
  protocol: string;
  minSeverity: string;
  enabled: boolean;
  /** Simulated reliability counter (M09 §4 tab 3) — 0 until the engine marks the target unreachable. */
  bufferedRows: number;
};

export type NetflowTargetDTO = {
  id: number;
  name: string;
  host: string;
  port: number;
  version: string;
  samplingRate: number;
  enabled: boolean;
};

export type ReportScheduleDTO = {
  id: number;
  name: string;
  range: string; // daily | weekly | monthly
  format: string; // pdf | html | csv | json
  sections: string[]; // traffic | threats | audit
  recipients: string | null;
  enabled: boolean;
  lastRunAt: string | null;
};

/** LOCKED /logs/stats payload (ENDPOINTS §11): series + ipsBySeverity. */
export type LogStats = {
  range: StatsRange;
  from: string;
  to: string;
  bucketMinutes: number;
  series: Array<{ key: "allow" | "deny" | "drop" | "reject"; points: Array<{ ts: string; count: number }> }>;
  ipsBySeverity: Array<{ key: string; count: number }>;
};

// ── shared filter → where helpers ───────────────────────────────────────────

function toDateFilter(since?: string, until?: string): { gte?: Date; lte?: Date } | undefined {
  const f: { gte?: Date; lte?: Date } = {};
  if (since) f.gte = new Date(since);
  if (until) f.lte = new Date(until);
  return Object.keys(f).length ? f : undefined;
}

function toPageMeta(page: number, limit: number, total: number): PageMeta {
  return { page, limit, total, totalPages: Math.max(1, Math.ceil(total / limit)) };
}

// ── firewall logs ───────────────────────────────────────────────────────────

function firewallWhere(tenantId: number, f: { q?: string; action?: string; src?: string; dst?: string; since?: string; until?: string }) {
  const where: Record<string, unknown> = { tenantId };
  if (f.action) where.action = f.action;
  if (f.src) where.srcIp = { startsWith: f.src };
  if (f.dst) where.dstIp = { startsWith: f.dst };
  const ts = toDateFilter(f.since, f.until);
  if (ts) where.timestamp = ts;
  if (f.q) {
    // Case-insensitive substring — SQLite LIKE semantics via Prisma `contains`.
    where.OR = ["srcIp", "dstIp", "userName", "ruleName", "appName"].map((col) => ({ [col]: { contains: f.q } }));
  }
  return where;
}

function toFirewallDTO(row: {
  id: number;
  timestamp: Date;
  srcIp: string | null;
  srcPort: number | null;
  dstIp: string | null;
  dstPort: number | null;
  protocol: string | null;
  action: string | null;
  ruleName: string | null;
  appName: string | null;
  bytes: number;
  packets: number;
  userName: string | null;
}): FirewallLogDTO {
  return {
    id: row.id,
    timestamp: row.timestamp.toISOString(),
    srcIp: row.srcIp,
    srcPort: row.srcPort,
    dstIp: row.dstIp,
    dstPort: row.dstPort,
    protocol: row.protocol,
    action: row.action,
    ruleName: row.ruleName,
    appName: row.appName,
    bytes: row.bytes,
    packets: row.packets,
    userName: row.userName,
  };
}

export async function listFirewallLogs(
  tenantId: number,
  filters: FirewallLogQuery,
): Promise<{ rows: FirewallLogDTO[]; meta: PageMeta }> {
  const where = firewallWhere(tenantId, filters);
  const [rows, total] = await Promise.all([
    db.firewallLog.findMany({
      where,
      orderBy: { timestamp: "desc" },
      skip: (filters.page - 1) * filters.limit,
      take: filters.limit,
    }),
    db.firewallLog.count({ where }),
  ]);
  return { rows: rows.map(toFirewallDTO), meta: toPageMeta(filters.page, filters.limit, total) };
}

const EXPORT_CAP = 10_000;

const CSV_HEADER = "timestamp,src_ip,src_port,dst_ip,dst_port,protocol,action,rule_name,app_name,bytes,packets,user_name,id";

function csvCell(v: unknown): string {
  if (v === null || v === undefined) return "";
  const s = String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** Same filters as the list, no page — newest first, hard cap 10 000 rows (M09 §3). */
export async function exportFirewallLogsCsv(tenantId: number, filters: FirewallExportQuery): Promise<string> {
  const where = firewallWhere(tenantId, filters);
  const rows = await db.firewallLog.findMany({
    where,
    orderBy: { timestamp: "desc" },
    take: EXPORT_CAP,
  });
  const lines = rows.map((r) =>
    [
      r.timestamp.toISOString(),
      csvCell(r.srcIp),
      r.srcPort ?? "",
      csvCell(r.dstIp),
      r.dstPort ?? "",
      csvCell(r.protocol),
      csvCell(r.action),
      csvCell(r.ruleName),
      csvCell(r.appName),
      r.bytes,
      r.packets,
      csvCell(r.userName),
      r.id,
    ].join(","),
  );
  return [CSV_HEADER, ...lines].join("\n");
}

// ── IPS events ──────────────────────────────────────────────────────────────

function toIpsDTO(row: {
  id: number;
  timestamp: Date;
  srcIp: string | null;
  srcPort: number | null;
  dstIp: string | null;
  dstPort: number | null;
  action: string;
  sid: string | null;
  severity: string;
  category: string | null;
  message: string | null;
  suppressedUntil: Date | null;
}): IpsEventDTO {
  return {
    id: row.id,
    timestamp: row.timestamp.toISOString(),
    srcIp: row.srcIp,
    srcPort: row.srcPort,
    dstIp: row.dstIp,
    dstPort: row.dstPort,
    action: row.action,
    sid: row.sid,
    severity: row.severity,
    category: row.category,
    message: row.message,
    suppressedUntil: row.suppressedUntil ? row.suppressedUntil.toISOString() : null,
  };
}

export async function listIpsEvents(
  tenantId: number,
  filters: IpsLogQuery,
): Promise<{ rows: IpsEventDTO[]; meta: PageMeta }> {
  const where: Record<string, unknown> = { tenantId };
  const severities = (filters.severity ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (severities.length) where.severity = { in: severities };
  if (filters.category) where.category = filters.category;
  const ts = toDateFilter(filters.since, filters.until);
  if (ts) where.timestamp = ts;
  if (filters.q) {
    where.OR = ["message", "sid", "srcIp", "dstIp", "category"].map((col) => ({ [col]: { contains: filters.q } }));
  }
  const [rows, total] = await Promise.all([
    db.ipsEvent.findMany({
      where,
      orderBy: { timestamp: "desc" },
      skip: (filters.page - 1) * filters.limit,
      take: filters.limit,
    }),
    db.ipsEvent.count({ where }),
  ]);
  return { rows: rows.map(toIpsDTO), meta: toPageMeta(filters.page, filters.limit, total) };
}

// ── audit log (append-only, read-only here — ADR-011) ───────────────────────

function toAuditDTO(row: {
  id: number;
  createdAt: Date;
  userId: number | null;
  username: string | null;
  sourceIp: string | null;
  action: string;
  objectType: string;
  objectId: number | null;
  objectName: string | null;
  beforeState: string | null;
  afterState: string | null;
  result: string;
}): AuditLogDTO {
  return {
    id: row.id,
    createdAt: row.createdAt.toISOString(),
    userId: row.userId,
    username: row.username,
    sourceIp: row.sourceIp,
    action: row.action,
    objectType: row.objectType,
    objectId: row.objectId,
    objectName: row.objectName,
    beforeState: row.beforeState,
    afterState: row.afterState,
    result: row.result,
  };
}

export async function listAuditLogs(
  tenantId: number,
  filters: AuditLogQuery,
): Promise<{ rows: AuditLogDTO[]; meta: PageMeta }> {
  const where: Record<string, unknown> = { tenantId };
  if (filters.user) where.username = { contains: filters.user };
  if (filters.objectType) where.objectType = filters.objectType;
  if (filters.result) where.result = filters.result;
  const ts = toDateFilter(filters.since, filters.until);
  if (ts) where.createdAt = ts;
  if (filters.q) {
    where.OR = ["action", "objectName", "username"].map((col) => ({ [col]: { contains: filters.q } }));
  }
  const [rows, total] = await Promise.all([
    db.auditLog.findMany({
      where,
      orderBy: { createdAt: "desc" },
      skip: (filters.page - 1) * filters.limit,
      take: filters.limit,
    }),
    db.auditLog.count({ where }),
  ]);
  return { rows: rows.map(toAuditDTO), meta: toPageMeta(filters.page, filters.limit, total) };
}

/** Distinct objectTypes observed — feeds the audit view's filter Select (M09 §4). */
export async function distinctAuditObjectTypes(tenantId: number): Promise<string[]> {
  const grouped = await db.auditLog.groupBy({
    by: ["objectType"],
    where: { tenantId },
    _count: { _all: true },
    orderBy: { _count: { objectType: "desc" } },
  });
  return grouped.map((g) => g.objectType);
}

// ── stats aggregation (LOCKED payload shape, ENDPOINTS §11) ────────────────

const RANGE_MINUTES: Record<StatsRange, { minutes: number; bucketMinutes: number }> = {
  "1h": { minutes: 60, bucketMinutes: 5 },
  "24h": { minutes: 24 * 60, bucketMinutes: 60 },
  "7d": { minutes: 7 * 24 * 60, bucketMinutes: 360 },
};

const ACTION_KEYS = ["allow", "deny", "drop", "reject"] as const;
const SEVERITY_KEYS = ["info", "low", "medium", "high", "critical"] as const;

export async function getLogStats(tenantId: number, range: StatsRange): Promise<LogStats> {
  const { minutes, bucketMinutes } = RANGE_MINUTES[range];
  const to = new Date();
  const from = new Date(to.getTime() - minutes * 60_000);
  const bucketMs = bucketMinutes * 60_000;
  const bucketCount = Math.ceil((to.getTime() - from.getTime()) / bucketMs);

  // Aggregate in JS from the window's rows — fine at simulation volumes
  // (firewall_logs ≤ 50 000, ips_events ≤ 5 000; DATA_LIFECYCLE §4 caps).
  const [flows, threats] = await Promise.all([
    db.firewallLog.findMany({
      where: { tenantId, timestamp: { gte: from, lte: to } },
      select: { timestamp: true, action: true },
    }),
    db.ipsEvent.findMany({
      where: { tenantId, timestamp: { gte: from, lte: to } },
      select: { severity: true },
    }),
  ]);

  const mkPoints = () =>
    Array.from({ length: bucketCount }, (_, i) => ({
      ts: new Date(from.getTime() + i * bucketMs).toISOString(),
      count: 0,
    }));
  const series = ACTION_KEYS.map((key) => ({ key, points: mkPoints() }));
  const idxOf = (ts: Date) => Math.min(bucketCount - 1, Math.max(0, Math.floor((ts.getTime() - from.getTime()) / bucketMs)));

  const sevCounts = new Map<string, number>(SEVERITY_KEYS.map((k) => [k, 0]));
  for (const f of flows) {
    const seriesEntry = series.find((s) => s.key === f.action);
    if (seriesEntry) seriesEntry.points[idxOf(f.timestamp)].count += 1;
  }
  for (const t of threats) {
    sevCounts.set(t.severity, (sevCounts.get(t.severity) ?? 0) + 1);
  }

  return {
    range,
    from: from.toISOString(),
    to: to.toISOString(),
    bucketMinutes,
    series,
    ipsBySeverity: [...sevCounts.entries()].map(([key, count]) => ({ key, count })),
  };
}

// ── syslog targets ──────────────────────────────────────────────────────────

function toSyslogDTO(row: {
  id: number;
  name: string;
  host: string;
  port: number;
  protocol: string;
  minSeverity: string;
  enabled: boolean;
}): SyslogTargetDTO {
  return {
    id: row.id,
    name: row.name,
    host: row.host,
    port: row.port,
    protocol: row.protocol,
    minSeverity: row.minSeverity,
    enabled: row.enabled,
    bufferedRows: 0, // model carries no counter; engine-owned when appliance-side
  };
}

export async function listSyslogTargets(tenantId: number): Promise<SyslogTargetDTO[]> {
  const rows = await db.syslogTarget.findMany({ where: { tenantId }, orderBy: { id: "asc" } });
  return rows.map(toSyslogDTO);
}

export async function createSyslogTarget(tenantId: number, body: SyslogTargetCreate): Promise<SyslogTargetDTO> {
  const dup = await db.syslogTarget.findFirst({ where: { tenantId, name: body.name } });
  if (dup) throw ApiError.conflict(`A syslog target named "${body.name}" already exists`);
  const row = await db.syslogTarget.create({ data: { tenantId, ...body } });
  return toSyslogDTO(row);
}

export async function updateSyslogTarget(tenantId: number, id: number, body: SyslogTargetUpdate): Promise<SyslogTargetDTO> {
  const existing = await db.syslogTarget.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("Syslog target not found");
  if (body.name && body.name !== existing.name) {
    const dup = await db.syslogTarget.findFirst({ where: { tenantId, name: body.name } });
    if (dup) throw ApiError.conflict(`A syslog target named "${body.name}" already exists`);
  }
  const row = await db.syslogTarget.update({ where: { id }, data: body });
  return toSyslogDTO(row);
}

export async function deleteSyslogTarget(tenantId: number, id: number): Promise<void> {
  const existing = await db.syslogTarget.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("Syslog target not found");
  await db.syslogTarget.delete({ where: { id } });
}

// ── netflow targets ─────────────────────────────────────────────────────────

export async function listNetflowTargets(tenantId: number): Promise<NetflowTargetDTO[]> {
  const rows = await db.netflowTarget.findMany({ where: { tenantId }, orderBy: { id: "asc" } });
  return rows.map((r) => ({
    id: r.id,
    name: r.name,
    host: r.host,
    port: r.port,
    version: r.version,
    samplingRate: r.samplingRate,
    enabled: r.enabled,
  }));
}

export async function createNetflowTarget(tenantId: number, body: NetflowTargetCreate): Promise<NetflowTargetDTO> {
  const dup = await db.netflowTarget.findFirst({ where: { tenantId, name: body.name } });
  if (dup) throw ApiError.conflict(`A NetFlow target named "${body.name}" already exists`);
  const row = await db.netflowTarget.create({ data: { tenantId, ...body } });
  return { id: row.id, name: row.name, host: row.host, port: row.port, version: row.version, samplingRate: row.samplingRate, enabled: row.enabled };
}

export async function updateNetflowTarget(tenantId: number, id: number, body: NetflowTargetUpdate): Promise<NetflowTargetDTO> {
  const existing = await db.netflowTarget.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("NetFlow target not found");
  if (body.name && body.name !== existing.name) {
    const dup = await db.netflowTarget.findFirst({ where: { tenantId, name: body.name } });
    if (dup) throw ApiError.conflict(`A NetFlow target named "${body.name}" already exists`);
  }
  const row = await db.netflowTarget.update({ where: { id }, data: body });
  return { id: row.id, name: row.name, host: row.host, port: row.port, version: row.version, samplingRate: row.samplingRate, enabled: row.enabled };
}

export async function deleteNetflowTarget(tenantId: number, id: number): Promise<void> {
  const existing = await db.netflowTarget.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("NetFlow target not found");
  await db.netflowTarget.delete({ where: { id } });
}

// ── report schedules ────────────────────────────────────────────────────────

function toScheduleDTO(row: {
  id: number;
  name: string;
  range: string;
  format: string;
  sections: string;
  recipients: string | null;
  enabled: boolean;
  lastRunAt: Date | null;
}): ReportScheduleDTO {
  return {
    id: row.id,
    name: row.name,
    range: row.range,
    format: row.format,
    sections: parseJson<string[]>(row.sections, []),
    recipients: row.recipients,
    enabled: row.enabled,
    lastRunAt: row.lastRunAt ? row.lastRunAt.toISOString() : null,
  };
}

export async function listReportSchedules(tenantId: number): Promise<ReportScheduleDTO[]> {
  const rows = await db.reportSchedule.findMany({ where: { tenantId }, orderBy: { id: "asc" } });
  return rows.map(toScheduleDTO);
}

export async function createReportSchedule(tenantId: number, body: ReportScheduleCreate): Promise<ReportScheduleDTO> {
  const dup = await db.reportSchedule.findFirst({ where: { tenantId, name: body.name } });
  if (dup) throw ApiError.conflict(`A schedule named "${body.name}" already exists`);
  const row = await db.reportSchedule.create({
    data: {
      tenantId,
      name: body.name,
      range: body.range,
      format: body.format,
      sections: JSON.stringify(body.sections),
      recipients: body.recipients ?? null,
      enabled: body.enabled,
    },
  });
  return toScheduleDTO(row);
}

export async function updateReportSchedule(tenantId: number, id: number, body: ReportScheduleUpdate): Promise<ReportScheduleDTO> {
  const existing = await db.reportSchedule.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("Report schedule not found");
  if (body.name && body.name !== existing.name) {
    const dup = await db.reportSchedule.findFirst({ where: { tenantId, name: body.name } });
    if (dup) throw ApiError.conflict(`A schedule named "${body.name}" already exists`);
  }
  const { sections, recipients, ...rest } = body;
  const row = await db.reportSchedule.update({
    where: { id },
    data: {
      ...rest,
      ...(sections ? { sections: JSON.stringify(sections) } : {}),
      ...(recipients !== undefined ? { recipients: recipients ?? null } : {}),
    },
  });
  return toScheduleDTO(row);
}

export async function deleteReportSchedule(tenantId: number, id: number): Promise<void> {
  const existing = await db.reportSchedule.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("Report schedule not found");
  await db.reportSchedule.delete({ where: { id } });
}

/** Run now (simulated) — bumps lastRunAt only; the payload is the Reports view itself. */
export async function runReportSchedule(tenantId: number, id: number): Promise<{ ok: true; lastRunAt: string }> {
  const existing = await db.reportSchedule.findFirst({ where: { tenantId, id } });
  if (!existing) throw ApiError.notFound("Report schedule not found");
  const lastRunAt = new Date();
  await db.reportSchedule.update({ where: { id }, data: { lastRunAt } });
  return { ok: true, lastRunAt: lastRunAt.toISOString() };
}
