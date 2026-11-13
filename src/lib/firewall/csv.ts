/**
 * CSV serialize/parse for firewall-rules export + import (M03 §3).
 * Columns (fixed order): position,name,enabled,action,srcZones,dstZones,
 * srcAddrs,dstAddrs,services,logging,tags,comment. Multi-value cells hold a
 * comma-separated list inside standard RFC-4180 quotes; import also accepts
 * numeric ids in place of names.
 */

export const CSV_COLUMNS = [
  "position",
  "name",
  "enabled",
  "action",
  "srcZones",
  "dstZones",
  "srcAddrs",
  "dstAddrs",
  "services",
  "logging",
  "tags",
  "comment",
] as const;

export function csvEscape(cell: string): string {
  if (/[",\n\r]/.test(cell)) return `"${cell.replace(/"/g, '""')}"`;
  return cell;
}

export function csvRow(cells: string[]): string {
  return cells.map(csvEscape).join(",");
}

/** Minimal RFC-4180 parser (quoted cells, doubled quotes, CRLF/LF). */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let inQuotes = false;
  const src = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    if (inQuotes) {
      if (ch === '"') {
        if (src[i + 1] === '"') {
          cell += '"';
          i++;
        } else inQuotes = false;
      } else cell += ch;
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ",") {
      row.push(cell);
      cell = "";
    } else if (ch === "\n") {
      row.push(cell);
      rows.push(row);
      row = [];
      cell = "";
    } else cell += ch;
  }
  if (cell !== "" || row.length > 0) {
    row.push(cell);
    rows.push(row);
  }
  return rows.filter((r) => r.some((c) => c.trim() !== ""));
}

export interface NameResolver {
  zone: Map<string, number>; // lowercased name → id
  addr: Map<string, number>;
  service: Map<string, number>;
}

export interface CsvRuleDraft {
  position?: number;
  name: string;
  enabled: boolean;
  action: string;
  srcZoneIds: number[];
  dstZoneIds: number[];
  srcAddrIds: number[];
  dstAddrIds: number[];
  serviceIds: number[];
  logging: string;
  tags: string[];
  comment: string | null;
}

export interface CsvParseResult {
  drafts: CsvRuleDraft[];
  errors: Array<{ row: number; message: string }>;
}

function splitList(cell: string): string[] {
  return cell
    .split(/[,;]/)
    .map((s) => s.trim())
    .filter((s) => s !== "" && s !== "-");
}

export function csvToDrafts(text: string, resolver: NameResolver): CsvParseResult {
  const rows = parseCsv(text);
  const drafts: CsvRuleDraft[] = [];
  const errors: Array<{ row: number; message: string }> = [];

  const body = rows[0] && rows[0][0]?.trim().toLowerCase() === "position" ? rows.slice(1) : rows;

  const asIds = (cell: string, map: Map<string, number>, kind: string): number[] | string => {
    const out: number[] = [];
    for (const token of splitList(cell)) {
      if (/^\d+$/.test(token)) {
        out.push(Number(token));
        continue;
      }
      const id = map.get(token.toLowerCase());
      if (id == null) return `unknown ${kind} name '${token}'`;
      out.push(id);
    }
    return out;
  };

  body.forEach((r, idx) => {
    const rowNo = idx + 1;
    if (r.length < CSV_COLUMNS.length) {
      errors.push({ row: rowNo, message: `expected ${CSV_COLUMNS.length} columns, got ${r.length}` });
      return;
    }
    const [pos, name, enabled, action, srcZones, dstZones, srcAddrs, dstAddrs, services, logging, tags, comment] =
      r.map((c) => c.trim());
    if (!name) {
      errors.push({ row: rowNo, message: "name is required" });
      return;
    }
    if (!["allow", "deny", "drop", "reject"].includes(action)) {
      errors.push({ row: rowNo, message: `invalid action '${action}' (allow|deny|drop|reject)` });
      return;
    }
    if (!["none", "summary", "detail"].includes(logging)) {
      errors.push({ row: rowNo, message: `invalid logging '${logging}' (none|summary|detail)` });
      return;
    }
    const srcZ = asIds(srcZones, resolver.zone, "zone");
    if (typeof srcZ === "string") return void errors.push({ row: rowNo, message: srcZ });
    const dstZ = asIds(dstZones, resolver.zone, "zone");
    if (typeof dstZ === "string") return void errors.push({ row: rowNo, message: dstZ });
    const srcA = asIds(srcAddrs, resolver.addr, "address object/group");
    if (typeof srcA === "string") return void errors.push({ row: rowNo, message: srcA });
    const dstA = asIds(dstAddrs, resolver.addr, "address object/group");
    if (typeof dstA === "string") return void errors.push({ row: rowNo, message: dstA });
    const svcs = asIds(services, resolver.service, "service object/group");
    if (typeof svcs === "string") return void errors.push({ row: rowNo, message: svcs });

    drafts.push({
      position: pos && /^\d+$/.test(pos) ? Number(pos) : undefined,
      name,
      enabled: ["true", "1", "yes"].includes(enabled.toLowerCase()),
      action,
      srcZoneIds: srcZ,
      dstZoneIds: dstZ,
      srcAddrIds: srcA,
      dstAddrIds: dstA,
      serviceIds: svcs,
      logging,
      tags: splitList(tags),
      comment: comment || null,
    });
  });

  return { drafts, errors };
}
