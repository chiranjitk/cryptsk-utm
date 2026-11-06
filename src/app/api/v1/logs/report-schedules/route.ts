/**
 * Scheduled reports (M09 §3, spec §1.12) — GET list + POST create.
 * Mutations audit `report_schedule.create` and snapshot section `system`.
 */

import { route } from "@/lib/api/handler";
import { reportScheduleCreateSchema } from "@/lib/validators/logs";
import { createReportSchedule, listReportSchedules } from "@/lib/logs/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "reports" }, async ({ auth }) => {
  return { data: await listReportSchedules(auth.tenantId) };
});

export const POST = route(
  { area: "reports", bodySchema: reportScheduleCreateSchema, section: "system" },
  async ({ auth, body }) => {
    const created = await createReportSchedule(auth.tenantId, body);
    return {
      data: created,
      audit: { action: "report_schedule.create", objectType: "report_schedule", objectId: created.id, objectName: created.name, after: created },
    };
  },
);
