/**
 * M12 CEF / LEEF export (spec 2.13 §8) — text/plain attachment download.
 *
 * Format conventions followed literally:
 *   CEF  v0:   CEF:0|Vendor|Product|Device Version|Signature ID|Name|Severity|ext key=value pairs
 *              (rt = epoch milliseconds; `=`, `\` and newlines escaped in extension values)
 *   LEEF 2.0:  LEEF:2.0|Vendor|Product|Product Version|Event ID|<delimiter>|ext pairs
 *              (default delimiter = literal TAB; no backslash escaping in LEEF —
 *              delimiter/pipe/newline chars are replaced with spaces in values)
 * Read-only, area `logs`.
 */

import { NextResponse } from "next/server";
import { route } from "@/lib/api/handler";
import { logExportQuerySchema } from "@/lib/validators/reporting";
import { db } from "@/lib/db";

export const dynamic = "force-dynamic";

const FW_SEVERITY: Record<string, number> = { allow: 2, deny: 5, drop: 7, reject: 6 };
const IPS_SEVERITY: Record<string, number> = { info: 2, low: 3, medium: 5, high: 7, critical: 9 };

function cefValue(v: unknown): string {
  return String(v ?? "")
    .replace(/\\/g, "\\\\")
    .replace(/=/g, "\\=")
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "");
}

function cefHeaderField(v: string): string {
  return v.replace(/\\/g, "\\\\").replace(/\|/g, "\\|").replace(/\n/g, "\\n");
}

function leefValue(v: unknown): string {
  return String(v ?? "")
    .replace(/[\t|\n\r]/g, " ");
}

type FirewallRow = {
  timestamp: Date;
  srcIp: string | null;
  dstIp: string | null;
  srcPort: number | null;
  dstPort: number | null;
  protocol: string | null;
  action: string | null;
  ruleName: string | null;
  userName: string | null;
};

type IpsRow = {
  timestamp: Date;
  srcIp: string | null;
  dstIp: string | null;
  action: string;
  severity: string;
  category: string | null;
  sid: string | null;
  message: string | null;
};

function firewallToCef(r: FirewallRow): string {
  const ext = [
    `src=${cefValue(r.srcIp ?? "")}`,
    `dst=${cefValue(r.dstIp ?? "")}`,
    `act=${cefValue(r.action ?? "")}`,
    `rt=${r.timestamp.getTime()}`,
    r.protocol ? `proto=${cefValue(r.protocol)}` : null,
    r.srcPort != null ? `spt=${r.srcPort}` : null,
    r.dstPort != null ? `dpt=${r.dstPort}` : null,
    r.ruleName ? `cs1=${cefValue(r.ruleName)}` : null,
    r.ruleName ? "cs1Label=Rule" : null,
    r.userName ? `duser=${cefValue(r.userName)}` : null,
  ]
    .filter(Boolean)
    .join(" ");
  const sev = FW_SEVERITY[r.action ?? ""] ?? 5;
  return `CEF:0|${cefHeaderField("Cryptsk")}|${cefHeaderField("UTM")}|1.0|100|${cefHeaderField("Firewall event")}|${sev}|${ext}`;
}

function ipsToCef(r: IpsRow): string {
  const ext = [
    `src=${cefValue(r.srcIp ?? "")}`,
    `dst=${cefValue(r.dstIp ?? "")}`,
    `act=${cefValue(r.action)}`,
    `rt=${r.timestamp.getTime()}`,
    r.message ? `msg=${cefValue(r.message)}` : null,
    r.category ? `cs1=${cefValue(r.category)}` : null,
    r.category ? "cs1Label=Category" : null,
    r.sid ? `cs2=${cefValue(r.sid)}` : null,
    r.sid ? "cs2Label=SignatureID" : null,
  ]
    .filter(Boolean)
    .join(" ");
  const sev = IPS_SEVERITY[r.severity] ?? 5;
  return `CEF:0|${cefHeaderField("Cryptsk")}|${cefHeaderField("UTM")}|1.0|200|${cefHeaderField("IPS event")}|${sev}|${ext}`;
}

function firewallToLeef(r: FirewallRow): string {
  const ext = [
    `src=${leefValue(r.srcIp ?? "")}`,
    `dst=${leefValue(r.dstIp ?? "")}`,
    `act=${leefValue(r.action ?? "")}`,
    `devTime=${r.timestamp.getTime()}`,
    r.protocol ? `proto=${leefValue(r.protocol)}` : null,
    r.srcPort != null ? `srcPort=${r.srcPort}` : null,
    r.dstPort != null ? `dstPort=${r.dstPort}` : null,
    r.ruleName ? `cat=${leefValue(r.ruleName)}` : null,
    r.userName ? `usrName=${leefValue(r.userName)}` : null,
  ]
    .filter(Boolean)
    .join("\t");
  return `LEEF:2.0|Cryptsk|UTM|1.0|100|\t|${ext}`;
}

function ipsToLeef(r: IpsRow): string {
  const ext = [
    `src=${leefValue(r.srcIp ?? "")}`,
    `dst=${leefValue(r.dstIp ?? "")}`,
    `act=${leefValue(r.action)}`,
    `devTime=${r.timestamp.getTime()}`,
    r.category ? `cat=${leefValue(r.category)}` : null,
    r.severity ? `sevLevel=${IPS_SEVERITY[r.severity] ?? 5}` : null,
    r.sid ? `identHost=${leefValue(r.sid)}` : null,
    r.message ? `eventName=${leefValue(r.message)}` : null,
  ]
    .filter(Boolean)
    .join("\t");
  return `LEEF:2.0|Cryptsk|UTM|1.0|200|\t|${ext}`;
}

export const GET = route({ area: "logs", querySchema: logExportQuerySchema }, async ({ auth, query }) => {
  const { dataset, format, limit } = query;
  const take = Math.min(limit, 1000);

  let lines: string[];
  if (dataset === "firewall") {
    const rows = await db.firewallLog.findMany({
      where: { tenantId: auth.tenantId },
      orderBy: { timestamp: "desc" },
      take,
    });
    lines = rows.map((r) => (format === "cef" ? firewallToCef(r) : firewallToLeef(r)));
  } else {
    const rows = await db.ipsEvent.findMany({
      where: { tenantId: auth.tenantId },
      orderBy: { timestamp: "desc" },
      take,
    });
    lines = rows.map((r) => (format === "cef" ? ipsToCef(r) : ipsToLeef(r)));
  }

  const body = lines.length > 0 ? `${lines.join("\n")}\n` : "";
  // NextResponse passthrough — the route() wrapper returns it verbatim (with
  // the x-request-id header applied) so the download is not envelope-wrapped.
  const res = new NextResponse(body, {
    status: 200,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Content-Disposition": `attachment; filename="${dataset}-${format}-export.txt"`,
    },
  });
  return { data: res };
});
