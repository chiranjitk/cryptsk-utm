/**
 * GET /api/v1/logs/audit/export — CSV of the current audit filter (M09 §3
 * surface expansion, R6 logs QA round). Same filter params as `/logs/audit`
 * minus `facets`/`page`/`limit`; capped at 10 000 rows most-recent-first;
 * `X-Row-Cap` reports the cap. Shaped as a raw NextResponse like the other
 * export routes (handler passes it through with x-request-id; audit still
 * applies). `beforeState`/`afterState` JSON columns are deliberately NOT in
 * the CSV — they stay in the row drawer (M09 §4 audit view).
 */

import { NextResponse } from "next/server";
import { z } from "zod";
import { route } from "@/lib/api/handler";
import { auditResultSchema } from "@/lib/validators/enums";
import { db } from "@/lib/db";

export const dynamic = "force-dynamic";

const isoOrEmpty = z
  .string()
  .refine((v) => v === "" || !Number.isNaN(Date.parse(v)), "must be an ISO timestamp");

/** Same shape as auditLogQuerySchema minus facets/page/limit — filters only. */
const auditExportQuerySchema = z
  .object({
    user: z.string().max(64).optional(),
    objectType: z.string().max(64).optional(),
    result: auditResultSchema.optional(),
    q: z.string().max(128).optional(),
    since: isoOrEmpty.optional(),
    until: isoOrEmpty.optional(),
  })
  .refine(
    (data) =>
      !data.since || !data.until || data.since === "" || data.until === "" || Date.parse(data.until) >= Date.parse(data.since),
    { message: "until must not be earlier than since", path: ["until"] },
  );

const EXPORT_CAP = 10_000;

const CSV_HEADER = "timestamp,username,user_id,source_ip,action,object_type,object_id,object_name,result,id";

function csvCell(v: unknown): string {
  if (v === null || v === undefined) return "";
  const s = String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export const GET = route({ area: "audit", querySchema: auditExportQuerySchema }, async ({ auth, query }) => {
  // Same where semantics as listAuditLogs (service) — kept in sync there.
  const where: Record<string, unknown> = { tenantId: auth.tenantId };
  if (query.user) where.username = { contains: query.user };
  if (query.objectType) where.objectType = query.objectType;
  if (query.result) where.result = query.result;
  if (query.since || query.until) {
    const ts: Record<string, unknown> = {};
    if (query.since) ts.gte = new Date(query.since);
    if (query.until) ts.lte = new Date(query.until);
    where.createdAt = ts;
  }
  if (query.q) {
    where.OR = ["action", "objectName", "username"].map((col) => ({ [col]: { contains: query.q } }));
  }

  const rows = await db.auditLog.findMany({
    where,
    orderBy: { createdAt: "desc" },
    take: EXPORT_CAP,
  });

  const lines = rows.map((r) =>
    [
      r.createdAt.toISOString(),
      csvCell(r.username),
      r.userId ?? "",
      csvCell(r.sourceIp),
      csvCell(r.action),
      csvCell(r.objectType),
      r.objectId ?? "",
      csvCell(r.objectName),
      csvCell(r.result),
      r.id,
    ].join(","),
  );
  const csv = [CSV_HEADER, ...lines].join("\n");

  const res = new NextResponse(csv, {
    status: 200,
    headers: {
      "Content-Type": "text/csv; charset=utf-8",
      "Content-Disposition": 'attachment; filename="audit-log.csv"',
      "X-Row-Cap": String(EXPORT_CAP),
    },
  });
  return { data: res };
});
