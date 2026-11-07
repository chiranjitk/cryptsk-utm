/**
 * M12 report runs — GET single (full row incl. contentHtml) + DELETE.
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { toRunDetail } from "@/app/api/v1/reports/engine";

export const dynamic = "force-dynamic";

export const GET = route({ area: "reports" }, async ({ auth, params }) => {
  const id = Number(params.id);
  if (!Number.isInteger(id) || id <= 0) throw ApiError.validation("Invalid report run id");
  const row = await db.reportRun.findFirst({ where: { tenantId: auth.tenantId, id } });
  if (!row) throw ApiError.notFound("Report run not found");
  return { data: toRunDetail(row) };
});

export const DELETE = route({ area: "reports", section: "reports" }, async ({ auth, params }) => {
  const id = Number(params.id);
  if (!Number.isInteger(id) || id <= 0) throw ApiError.validation("Invalid report run id");
  const existing = await db.reportRun.findFirst({ where: { tenantId: auth.tenantId, id } });
  if (!existing) throw ApiError.notFound("Report run not found");
  await db.reportRun.delete({ where: { id } });
  return {
    data: { ok: true },
    audit: {
      action: "report.delete",
      objectType: "report_run",
      objectId: existing.id,
      objectName: existing.name,
      after: { id: existing.id, name: existing.name },
    },
  };
});
