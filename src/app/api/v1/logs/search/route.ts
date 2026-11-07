/**
 * M12 unified log search (spec 2.13 §1) — one endpoint, three datasets.
 * Normalizes firewall_logs / ips_events / audit_log rows into a single row
 * shape `{ id, dataset, ts, headline, detail, severity? }` with server-side
 * paging. Free-text `q` uses Prisma `contains` (SQLite LIKE is ASCII
 * case-insensitive); read-only, area `logs`.
 */

import { route } from "@/lib/api/handler";
import { unifiedSearchQuerySchema } from "@/lib/validators/reporting";
import { db } from "@/lib/db";
import { pageMetaOf } from "@/app/api/v1/reports/engine";

export const dynamic = "force-dynamic";

type SearchRow = {
  id: number;
  dataset: "firewall" | "ips" | "audit";
  ts: string;
  headline: string;
  detail: string;
  severity?: string;
};

function humanBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export const GET = route({ area: "logs", querySchema: unifiedSearchQuerySchema }, async ({ auth, query }) => {
  const { dataset, q, severity, action, since, until, page, limit } = query;
  const tsFilter: { gte?: Date; lte?: Date } = {
    ...(since ? { gte: new Date(since) } : {}),
    ...(until ? { lte: new Date(until) } : {}),
  };
  const hasTs = Object.keys(tsFilter).length > 0;
  const skip = (page - 1) * limit;

  let rows: SearchRow[];
  let total: number;

  if (dataset === "firewall") {
    const where: Record<string, unknown> = { tenantId: auth.tenantId };
    if (action) where.action = action;
    if (hasTs) where.timestamp = tsFilter;
    // spec: contains on src_ip, dst_ip, action, rule_name
    if (q) where.OR = ["srcIp", "dstIp", "action", "ruleName"].map((col) => ({ [col]: { contains: q } }));
    const [found, count] = await Promise.all([
      db.firewallLog.findMany({ where, orderBy: { timestamp: "desc" }, skip, take: limit }),
      db.firewallLog.count({ where }),
    ]);
    total = count;
    rows = found.map((r) => ({
      id: r.id,
      dataset: "firewall" as const,
      ts: r.timestamp.toISOString(),
      headline: `${r.srcIp ?? "?"} → ${r.dstIp ?? "?"} ${r.action ?? "?"}`.trim(),
      detail: [
        r.protocol ? String(r.protocol).toUpperCase() : null,
        r.srcPort != null && r.dstPort != null ? `${r.srcPort} → ${r.dstPort}` : null,
        r.ruleName ? `rule "${r.ruleName}"` : null,
        r.bytes > 0 ? humanBytes(r.bytes) : null,
        r.userName ? `user ${r.userName}` : null,
      ]
        .filter(Boolean)
        .join(" · "),
    }));
  } else if (dataset === "ips") {
    const where: Record<string, unknown> = { tenantId: auth.tenantId };
    if (severity) where.severity = severity;
    if (action) where.action = action;
    if (hasTs) where.timestamp = tsFilter;
    // spec: signature (message/sid), src_ip
    if (q) where.OR = ["message", "sid", "srcIp"].map((col) => ({ [col]: { contains: q } }));
    const [found, count] = await Promise.all([
      db.ipsEvent.findMany({ where, orderBy: { timestamp: "desc" }, skip, take: limit }),
      db.ipsEvent.count({ where }),
    ]);
    total = count;
    rows = found.map((r) => ({
      id: r.id,
      dataset: "ips" as const,
      ts: r.timestamp.toISOString(),
      headline: r.message ?? r.sid ?? r.category ?? `IPS event ${r.action}`,
      detail: [`${r.srcIp ?? "?"} → ${r.dstIp ?? "?"}`, r.action, r.category, r.sid ? `sid ${r.sid}` : null]
        .filter(Boolean)
        .join(" · "),
      severity: r.severity,
    }));
  } else {
    const where: Record<string, unknown> = { tenantId: auth.tenantId };
    // audit actions are dotted strings ("rule.create") — substring matches better than equality
    if (action) where.action = { contains: action };
    if (hasTs) where.createdAt = tsFilter;
    // spec: username, action, object_name
    if (q) where.OR = ["username", "action", "objectName"].map((col) => ({ [col]: { contains: q } }));
    const [found, count] = await Promise.all([
      db.auditLog.findMany({ where, orderBy: { createdAt: "desc" }, skip, take: limit }),
      db.auditLog.count({ where }),
    ]);
    total = count;
    rows = found.map((r) => ({
      id: r.id,
      dataset: "audit" as const,
      ts: r.createdAt.toISOString(),
      headline: `${r.username ?? "system"} → ${r.action}`,
      detail: [
        r.objectName ? `${r.objectType}:${r.objectName}` : r.objectType,
        r.result,
        r.sourceIp ? `from ${r.sourceIp}` : null,
      ]
        .filter(Boolean)
        .join(" · "),
    }));
  }

  return { data: rows, meta: pageMetaOf(page, limit, total) };
});
