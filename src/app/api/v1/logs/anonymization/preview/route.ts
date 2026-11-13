/**
 * M12 anonymization preview (spec 2.13 §7) — takes the last 5 rows of the
 * requested dataset, applies the tenant's enabled rules for that dataset to
 * the matching fields, and returns `{ before: [...], after: [...] }`.
 *
 * Strategies:
 *   hash         → sha256 hex, first 12 chars
 *   mask         → keep first octet + "x.x"  (192.168.1.10 → 192.x.x)
 *   pseudonymize → "user-<n>" where n is derived from sha256(value) — stable
 *                  per value across calls without extra state
 */

import { createHash } from "node:crypto";
import { route } from "@/lib/api/handler";
import { anonymizationPreviewQuerySchema } from "@/lib/validators/reporting";
import { db } from "@/lib/db";

export const dynamic = "force-dynamic";

export type AnonPreviewRow = Record<string, string | number | null>;

export type AnonPreview = { before: AnonPreviewRow[]; after: AnonPreviewRow[] };

function sha256Hex(v: string): string {
  return createHash("sha256").update(v).digest("hex");
}

export function applyStrategy(strategy: string, value: string): string {
  switch (strategy) {
    case "hash":
      return sha256Hex(value).slice(0, 12);
    case "mask": {
      const first = value.split(".")[0] ?? value;
      return `${first}.x.x`;
    }
    case "pseudonymize": {
      const n = 1 + (parseInt(sha256Hex(value).slice(0, 6), 16) % 998);
      return `user-${n}`;
    }
    default:
      return value;
  }
}

/** Which row keys each rule field touches per dataset. */
const FIELD_TARGETS: Record<string, Record<string, string[]>> = {
  firewall: { source_ip: ["srcIp", "dstIp"], user_name: ["userName"] },
  ips: { source_ip: ["srcIp", "dstIp"], user_name: [] },
  audit: { source_ip: ["sourceIp"], user_name: ["username"] },
  dns: { user_name: [], source_ip: [] },
  email: { user_name: ["username"], source_ip: ["sourceIp"] },
  waf: { source_ip: ["srcIp", "dstIp"] },
};

function toSerializedRows(
  dataset: string,
  rows: Array<Record<string, unknown>>,
): AnonPreviewRow[] {
  return rows.map((r) => {
    const base: AnonPreviewRow = { id: Number(r.id) };
    if (dataset === "audit") {
      base.ts = r.createdAt instanceof Date ? r.createdAt.toISOString() : null;
      base.username = (r.username as string | null) ?? null;
      base.sourceIp = (r.sourceIp as string | null) ?? null;
      base.action = (r.action as string | null) ?? null;
      base.objectType = (r.objectType as string | null) ?? null;
    } else {
      base.ts = r.timestamp instanceof Date ? r.timestamp.toISOString() : null;
      base.srcIp = (r.srcIp as string | null) ?? null;
      base.dstIp = (r.dstIp as string | null) ?? null;
      if (dataset === "firewall") {
        base.protocol = (r.protocol as string | null) ?? null;
        base.action = (r.action as string | null) ?? null;
        base.userName = (r.userName as string | null) ?? null;
      } else {
        base.severity = (r.severity as string | null) ?? null;
        base.category = (r.category as string | null) ?? null;
      }
    }
    return base;
  });
}

export const GET = route({ area: "reports", querySchema: anonymizationPreviewQuerySchema }, async ({ auth, query }) => {
  const { dataset } = query;
  const rules = await db.anonymizationRule.findMany({
    where: { tenantId: auth.tenantId, dataset, enabled: true },
    orderBy: { id: "asc" },
  });

  let rawRows: Array<Record<string, unknown>>;
  if (dataset === "firewall") {
    rawRows = await db.firewallLog.findMany({ where: { tenantId: auth.tenantId }, orderBy: { timestamp: "desc" }, take: 5 });
  } else if (dataset === "ips") {
    rawRows = await db.ipsEvent.findMany({ where: { tenantId: auth.tenantId }, orderBy: { timestamp: "desc" }, take: 5 });
  } else if (dataset === "audit") {
    rawRows = await db.auditLog.findMany({ where: { tenantId: auth.tenantId }, orderBy: { createdAt: "desc" }, take: 5 });
  } else {
    rawRows = []; // dns / email / waf datasets have no mock tables in the sandbox
  }

  const before = toSerializedRows(dataset, rawRows);
  const after: AnonPreviewRow[] = before.map((row) => ({ ...row }));

  for (const rule of rules) {
    const targets = FIELD_TARGETS[dataset]?.[rule.field] ?? [];
    for (const row of after) {
      for (const key of targets) {
        const value = row[key];
        if (typeof value === "string" && value.length > 0) {
          row[key] = applyStrategy(rule.strategy, value);
        }
      }
    }
  }

  return { data: { before, after } satisfies AnonPreview };
});
