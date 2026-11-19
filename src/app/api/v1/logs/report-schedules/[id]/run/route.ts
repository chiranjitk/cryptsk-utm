/**
 * POST /api/v1/logs/report-schedules/[id]/run — generate the report now
 * (M09 §3): bumps `lastRunAt` AND creates an actual ReportRun through the
 * report pipeline (F-e #15 — the schedule is no longer inert), audits
 * `report.run`, returns `{ ok, lastRunAt, run? }` — the console opens the
 * print view / download itself (run.id deep-links into the Reports tab).
 */

import { route, numericId } from "@/lib/api/handler";
import { runReportSchedule } from "@/lib/logs/service";

export const dynamic = "force-dynamic";

export const POST = route({ area: "reports", section: "system" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  const result = await runReportSchedule(auth.tenantId, id);
  return {
    data: result,
    audit: { action: "report.run", objectType: "report_schedule", objectId: id },
  };
});
