/** Report schedule item (M09 §3) — update / delete, audit `report_schedule.update|delete`. */

import { route } from "@/lib/api/handler";
import { reportScheduleUpdateSchema } from "@/lib/validators/logs";
import { deleteReportSchedule, updateReportSchedule } from "@/lib/logs/service";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "reports", bodySchema: reportScheduleUpdateSchema, section: "system" },
  async ({ auth, body, params }) => {
    const id = Number(params.id);
    const updated = await updateReportSchedule(auth.tenantId, id, body);
    return {
      data: updated,
      audit: { action: "report_schedule.update", objectType: "report_schedule", objectId: id, objectName: updated.name, after: updated },
    };
  },
);

export const DELETE = route({ area: "reports", section: "system" }, async ({ auth, params }) => {
  const id = Number(params.id);
  await deleteReportSchedule(auth.tenantId, id);
  return { data: { ok: true }, audit: { action: "report_schedule.delete", objectType: "report_schedule", objectId: id } };
});
