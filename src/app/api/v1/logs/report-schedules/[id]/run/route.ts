/**
 * POST /api/v1/logs/report-schedules/[id]/run — generate the report now
 * (simulated, M09 §3): bumps `lastRunAt`, audits `report.run`, returns
 * `{ ok, lastRunAt }` — the console opens the print view / download itself.
 */

import { route } from "@/lib/api/handler";
import { runReportSchedule } from "@/lib/logs/service";

export const dynamic = "force-dynamic";

export const POST = route({ area: "reports", section: "system" }, async ({ auth, params }) => {
  const id = Number(params.id);
  const result = await runReportSchedule(auth.tenantId, id);
  return {
    data: result,
    audit: { action: "report.run", objectType: "report_schedule", objectId: id },
  };
});
