/**
 * M12 report engine (spec 2.13) — computes section rollups from the real
 * `firewall_logs` / `ips_events` / `audit_log` tables, builds per-framework
 * compliance checklists, and renders a print-friendly HTML document (inline
 * CSS, blue-600 headings) stored in `ReportRun.contentHtml`.
 *
 * Shared by ad-hoc runs (POST /api/v1/reports/runs) and compliance runs
 * (POST /api/v1/logs/compliance/run). Server-side only (uses `db`).
 */

import { db } from "@/lib/db";
import { parseJson } from "@/lib/json";
import type { PageMeta } from "@/lib/api/envelope";
import type { ReportRangeExt, ReportSection } from "@/lib/validators/reporting";

// ── range windows ───────────────────────────────────────────────────────────

/** Coverage window per report range (days back from "now"). */
export const RANGE_DAYS: Record<ReportRangeExt, number> = {
  daily: 1,
  weekly: 7,
  monthly: 30,
  quarterly: 90,
};

export function rangeWindow(range: string): { since: Date; until: Date } {
  const days = RANGE_DAYS[range as ReportRangeExt] ?? 30;
  const until = new Date();
  return { since: new Date(until.getTime() - days * 86_400_000), until };
}

// ── summary shapes (stored as ReportRun.summary JSON) ───────────────────────

export interface ChecklistRow {
  control: string;
  pass: boolean;
  detail: string;
}

export interface CountRow {
  key: string;
  count: number;
  bytes: number;
}

export interface TrafficSummary {
  total: number;
  bytes: number;
  byAction: CountRow[];
  topSrc: CountRow[];
  topDst: CountRow[];
}

export interface ThreatsSummary {
  total: number;
  bySeverity: CountRow[];
  byCategory: CountRow[];
}

export interface AuditSummary {
  total: number;
  byAction: CountRow[];
  topUsers: CountRow[];
}

export interface ReportSummary {
  meta: {
    generatedAt: string;
    range: ReportRangeExt | string;
    since: string;
    until: string;
    /** format "pdf" → identical HTML + the view offers the print dialog. */
    pdfViaPrint: boolean;
  };
  framework?: string;
  checklist?: ChecklistRow[];
  passRate?: number;
  traffic?: TrafficSummary;
  threats?: ThreatsSummary;
  audit?: AuditSummary;
}

// ── section rollups (real tables, JS aggregation at sandbox volumes) ────────

export async function computeSectionSummary(
  tenantId: number,
  sections: ReportSection[],
  since: Date,
  until: Date,
): Promise<Pick<ReportSummary, "traffic" | "threats" | "audit">> {
  const out: Pick<ReportSummary, "traffic" | "threats" | "audit"> = {};
  const netWhere = { tenantId, timestamp: { gte: since, lte: until } };

  if (sections.includes("traffic")) {
    const [byAction, bySrc, byDst] = await Promise.all([
      db.firewallLog.groupBy({ by: ["action"], where: netWhere, _count: { _all: true }, _sum: { bytes: true } }),
      db.firewallLog.groupBy({
        by: ["srcIp"],
        where: netWhere,
        _count: { _all: true },
        _sum: { bytes: true },
        orderBy: { _count: { srcIp: "desc" } },
        take: 5,
      }),
      db.firewallLog.groupBy({
        by: ["dstIp"],
        where: netWhere,
        _count: { _all: true },
        _sum: { bytes: true },
        orderBy: { _count: { dstIp: "desc" } },
        take: 5,
      }),
    ]);
    const actionRows = byAction.map((g) => ({
      key: g.action ?? "(unknown)",
      count: g._count._all,
      bytes: g._sum.bytes ?? 0,
    }));
    const toRows = (list: Array<{ key: string | null; count: number; bytes: number }>): CountRow[] =>
      list.map((r) => ({ key: r.key ?? "(unknown)", count: r.count, bytes: r.bytes }));
    out.traffic = {
      total: actionRows.reduce((acc, r) => acc + r.count, 0),
      bytes: actionRows.reduce((acc, r) => acc + r.bytes, 0),
      byAction: toRows(actionRows).sort((a, b) => b.count - a.count),
      topSrc: toRows(bySrc.map((g) => ({ key: g.srcIp, count: g._count._all, bytes: g._sum.bytes ?? 0 }))),
      topDst: toRows(byDst.map((g) => ({ key: g.dstIp, count: g._count._all, bytes: g._sum.bytes ?? 0 }))),
    };
  }

  if (sections.includes("threats")) {
    const [bySeverity, byCategory] = await Promise.all([
      db.ipsEvent.groupBy({ by: ["severity"], where: netWhere, _count: { _all: true } }),
      db.ipsEvent.groupBy({
        by: ["category"],
        where: netWhere,
        _count: { _all: true },
        orderBy: { _count: { category: "desc" } },
        take: 10,
      }),
    ]);
    out.threats = {
      total: bySeverity.reduce((acc, g) => acc + g._count._all, 0),
      bySeverity: bySeverity
        .map((g) => ({ key: g.severity ?? "(unknown)", count: g._count._all, bytes: 0 }))
        .sort((a, b) => b.count - a.count),
      byCategory: byCategory.map((g) => ({ key: g.category ?? "uncategorized", count: g._count._all, bytes: 0 })),
    };
  }

  if (sections.includes("audit")) {
    const auditWhere = { tenantId, createdAt: { gte: since, lte: until } };
    const [byAction, byUser] = await Promise.all([
      db.auditLog.groupBy({
        by: ["action"],
        where: auditWhere,
        _count: { _all: true },
        orderBy: { _count: { action: "desc" } },
        take: 10,
      }),
      db.auditLog.groupBy({
        by: ["username"],
        where: auditWhere,
        _count: { _all: true },
        orderBy: { _count: { username: "desc" } },
        take: 5,
      }),
    ]);
    out.audit = {
      total: byAction.reduce((acc, g) => acc + g._count._all, 0),
      byAction: byAction.map((g) => ({ key: g.action, count: g._count._all, bytes: 0 })),
      topUsers: byUser.map((g) => ({ key: g.username ?? "(system)", count: g._count._all, bytes: 0 })),
    };
  }

  return out;
}

// ── per-framework compliance checklists ─────────────────────────────────────

const DAY = 86_400_000;

export async function buildChecklist(tenantId: number, framework: string): Promise<ChecklistRow[]> {
  const now = Date.now();
  switch (framework) {
    case "PCI": {
      const [totalFw, recentFw, auditCount, ips24h] = await Promise.all([
        db.firewallLog.count({ where: { tenantId } }),
        db.firewallLog.count({ where: { tenantId, timestamp: { gte: new Date(now - 90 * DAY) } } }),
        db.auditLog.count({ where: { tenantId } }),
        db.ipsEvent.count({ where: { tenantId, timestamp: { gte: new Date(now - DAY) } } }),
      ]);
      const pct = totalFw === 0 ? 0 : Math.round((recentFw / totalFw) * 100);
      return [
        {
          control: "Log retention ≥ 90 days",
          pass: totalFw > 0 && pct >= 95,
          detail: `${pct}% of ${totalFw} firewall events fall within the last 90 days`,
        },
        { control: "Audit trail enabled", pass: auditCount > 0, detail: `${auditCount} audit entries recorded` },
        { control: "IPS monitoring active", pass: ips24h > 0, detail: `${ips24h} IPS events in the last 24h` },
      ];
    }
    case "HIPAA": {
      const [total, withUser, last30] = await Promise.all([
        db.auditLog.count({ where: { tenantId } }),
        db.auditLog.count({ where: { tenantId, username: { not: null } } }),
        db.auditLog.count({ where: { tenantId, createdAt: { gte: new Date(now - 30 * DAY) } } }),
      ]);
      const pct = total === 0 ? 0 : Math.round((withUser / total) * 100);
      return [
        {
          control: "Access-audit coverage",
          pass: total > 0 && pct >= 90,
          detail: `${pct}% of ${total} audit entries carry an accountable user`,
        },
        {
          control: "Audit review cadence (30d)",
          pass: last30 > 0,
          detail: `${last30} audit entries in the last 30 days`,
        },
      ];
    }
    case "GDPR": {
      const [rules, fwRows] = await Promise.all([
        db.anonymizationRule.count({ where: { tenantId, enabled: true } }),
        db.firewallLog.count({ where: { tenantId } }),
      ]);
      return [
        {
          control: "Anonymization rules defined",
          pass: rules > 0,
          detail: `${rules} active anonymization rule(s) configured`,
        },
        {
          control: "Data-export availability",
          pass: fwRows > 0,
          detail: `Firewall dataset exportable — ${fwRows} rows available`,
        },
      ];
    }
    case "ISO27001": {
      const [audit24h, fw24h, ips7d] = await Promise.all([
        db.auditLog.count({ where: { tenantId, createdAt: { gte: new Date(now - DAY) } } }),
        db.firewallLog.count({ where: { tenantId, timestamp: { gte: new Date(now - DAY) } } }),
        db.ipsEvent.count({ where: { tenantId, timestamp: { gte: new Date(now - 7 * DAY) } } }),
      ]);
      return [
        { control: "Event logging policy", pass: audit24h > 0, detail: `${audit24h} audit entries in the last 24h` },
        { control: "Network monitoring", pass: fw24h > 0, detail: `${fw24h} firewall events in the last 24h` },
        { control: "Threat detection coverage", pass: ips7d > 0, detail: `${ips7d} IPS events in the last 7 days` },
      ];
    }
    case "SOC2": {
      const [changes, users] = await Promise.all([
        db.auditLog.count({
          where: {
            tenantId,
            createdAt: { gte: new Date(now - 30 * DAY) },
            OR: [
              { action: { contains: ".create" } },
              { action: { contains: ".update" } },
              { action: { contains: ".delete" } },
            ],
          },
        }),
        db.auditLog.groupBy({
          by: ["username"],
          where: { tenantId, createdAt: { gte: new Date(now - 30 * DAY) } },
          _count: { _all: true },
        }),
      ]);
      return [
        {
          control: "Change management trail",
          pass: changes > 0,
          detail: `${changes} create/update/delete audit entries in the last 30 days`,
        },
        {
          control: "Access reviews",
          pass: users.length > 0,
          detail: `${users.length} distinct account(s) active in the audit trail (30d)`,
        },
      ];
    }
    default:
      return [{ control: "Framework not recognized", pass: false, detail: `No checks defined for "${framework}"` }];
  }
}

// ── HTML rendering (inline CSS, print-friendly, blue-600 headings) ──────────

function esc(v: unknown): string {
  return String(v ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function humanBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

const TBL_STYLE = "width:100%;border-collapse:collapse;margin:8px 0 20px;font-size:12px";
const TH_STYLE =
  "text-align:left;padding:7px 10px;background:#eff6ff;color:#1d4ed8;border:1px solid #dbeafe;font-weight:600";
const TD_STYLE = "padding:6px 10px;border:1px solid #e4e4e7";

function htmlTable(headers: string[], rows: Array<Array<string | number>>): string {
  const head = headers.map((h) => `<th style="${TH_STYLE}">${esc(h)}</th>`).join("");
  const body = rows
    .map((r) => `<tr>${r.map((c) => `<td style="${TD_STYLE}">${esc(c)}</td>`).join("")}</tr>`)
    .join("");
  return `<table style="${TBL_STYLE}"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
}

function sectionHeading(text: string): string {
  return `<h2 style="margin:24px 0 4px;font-size:15px;color:#2563eb;border-bottom:2px solid #dbeafe;padding-bottom:4px">${esc(text)}</h2>`;
}

function countTable(title: string, headers: string[], rows: CountRow[], withBytes: boolean): string {
  const body = rows.map((r) => [r.key, r.count, ...(withBytes ? [humanBytes(r.bytes)] : [])] as Array<string | number>);
  const fallback = withBytes ? ["—", 0, "0 B"] : ["—", 0];
  return `${sectionHeading(title)}${htmlTable(headers, body.length ? body : [fallback])}`;
}

function renderSummarySections(summary: ReportSummary): string {
  let html = "";
  if (summary.traffic) {
    html += sectionHeading("Traffic");
    html += htmlTable(["Metric", "Value"], [
      ["Total connections", summary.traffic.total],
      ["Total bytes", humanBytes(summary.traffic.bytes)],
    ]);
    html += countTable("Connections by action", ["Action", "Count", "Bytes"], summary.traffic.byAction, true);
    html += countTable("Top 5 sources", ["Source IP", "Connections", "Bytes"], summary.traffic.topSrc, true);
    html += countTable("Top 5 destinations", ["Destination IP", "Connections", "Bytes"], summary.traffic.topDst, true);
  }
  if (summary.threats) {
    html += sectionHeading("Threats");
    html += countTable("IPS events by severity", ["Severity", "Count"], summary.threats.bySeverity, false);
    html += countTable("IPS events by category", ["Category", "Count"], summary.threats.byCategory, false);
  }
  if (summary.audit) {
    html += sectionHeading("Audit");
    html += countTable("Audit actions", ["Action", "Count"], summary.audit.byAction, false);
    html += countTable("Top users", ["User", "Entries"], summary.audit.topUsers, false);
  }
  return html;
}

function renderChecklist(checklist: ChecklistRow[]): string {
  const rows: Array<Array<string | number>> = checklist.map((r) => [
    r.control,
    r.pass ? "✓ PASS" : "✗ FAIL",
    r.detail,
  ]);
  return `${sectionHeading("Compliance checklist")}${htmlTable(["Control", "Result", "Detail"], rows.length ? rows : [["—", "—", "—"]])}`;
}

export function buildReportHtml(opts: {
  title: string;
  tenantName: string;
  range: string;
  generatedAt: Date;
  summary: ReportSummary;
}): string {
  const generated = `${opts.generatedAt.toISOString().replace("T", " ").slice(0, 19)} UTC`;
  const checklist = opts.summary.checklist ? renderChecklist(opts.summary.checklist) : "";
  const passRate =
    opts.summary.passRate !== undefined
      ? `<div style="margin:12px 0;padding:10px 14px;background:#eff6ff;border:1px solid #dbeafe;border-radius:6px;font-size:13px;color:#1d4ed8"><strong>Pass rate: ${opts.summary.passRate}%</strong> (${esc(opts.summary.framework ?? "")} controls)</div>`
      : "";
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>${esc(opts.title)}</title></head>
<body style="margin:0;padding:28px 32px;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;background:#ffffff;color:#18181b">
  <header style="display:flex;justify-content:space-between;align-items:baseline;gap:16px;border-bottom:3px solid #2563eb;padding-bottom:12px;margin-bottom:8px">
    <div>
      <h1 style="margin:0;font-size:21px;color:#2563eb">${esc(opts.title)}</h1>
      <p style="margin:4px 0 0;font-size:12px;color:#71717a">Tenant: ${esc(opts.tenantName)} &nbsp;&middot;&nbsp; Range: ${esc(opts.range)} &nbsp;&middot;&nbsp; Generated: ${generated}</p>
    </div>
    <div style="font-size:12px;font-weight:600;color:#2563eb;white-space:nowrap">Cryptsk UTM Console</div>
  </header>
  ${passRate}
  ${checklist}
  ${renderSummarySections(opts.summary)}
  <footer style="margin-top:28px;padding-top:10px;border-top:1px solid #e4e4e7;font-size:11px;color:#a1a1aa">Cryptsk Console — simulated data</footer>
</body>
</html>`;
}

// ── ReportRun DTO mappers (shared by runs + compliance routes) ──────────────

export type ReportRunListItem = {
  id: number;
  name: string;
  source: string;
  templateId: number | null;
  range: string;
  format: string;
  sections: string[];
  status: string;
  summary: ReportSummary | null;
  error: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  createdAt: string;
};

export type ReportRunDetail = ReportRunListItem & { contentHtml: string | null };

type RunRow = {
  id: number;
  name: string;
  source: string;
  templateId: number | null;
  range: string;
  format: string;
  sections: string;
  status: string;
  summary: string;
  contentHtml?: string | null;
  error: string | null;
  startedAt: Date | null;
  finishedAt: Date | null;
  createdAt: Date;
};

function baseDto(row: RunRow): ReportRunListItem {
  return {
    id: row.id,
    name: row.name,
    source: row.source,
    templateId: row.templateId,
    range: row.range,
    format: row.format,
    sections: parseJson<string[]>(row.sections, []),
    status: row.status,
    summary: parseJson<ReportSummary | null>(row.summary, null),
    error: row.error,
    startedAt: row.startedAt ? row.startedAt.toISOString() : null,
    finishedAt: row.finishedAt ? row.finishedAt.toISOString() : null,
    createdAt: row.createdAt.toISOString(),
  };
}

export function toRunListItem(row: RunRow): ReportRunListItem {
  return baseDto(row);
}

export function toRunDetail(row: RunRow & { contentHtml: string | null }): ReportRunDetail {
  return { ...baseDto(row), contentHtml: row.contentHtml };
}

export function pageMetaOf(page: number, limit: number, total: number): PageMeta {
  return { page, limit, total, totalPages: Math.max(1, Math.ceil(total / limit)) };
}
