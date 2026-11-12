/** Syslog target item (M09 §3) — update / delete, audit `syslog_target.update|delete`. */

import { route, numericId } from "@/lib/api/handler";
import { syslogTargetUpdateSchema } from "@/lib/validators/logs";
import { deleteSyslogTarget, updateSyslogTarget } from "@/lib/logs/service";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "log_forwarding", bodySchema: syslogTargetUpdateSchema, section: "system" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const updated = await updateSyslogTarget(auth.tenantId, id, body);
    return {
      data: updated,
      audit: { action: "syslog_target.update", objectType: "syslog_target", objectId: id, objectName: updated.name, after: updated },
    };
  },
);

export const DELETE = route({ area: "log_forwarding", section: "system" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  await deleteSyslogTarget(auth.tenantId, id);
  return { data: { ok: true }, audit: { action: "syslog_target.delete", objectType: "syslog_target", objectId: id } };
});
