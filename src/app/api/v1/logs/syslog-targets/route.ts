/**
 * Syslog forwarding targets (M09 §3) — GET list + POST create.
 * Mutations audit `syslog_target.create` and snapshot section `system`.
 */

import { route } from "@/lib/api/handler";
import { syslogTargetCreateSchema } from "@/lib/validators/logs";
import { createSyslogTarget, listSyslogTargets } from "@/lib/logs/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "log_forwarding" }, async ({ auth }) => {
  return { data: await listSyslogTargets(auth.tenantId) };
});

export const POST = route(
  { area: "log_forwarding", bodySchema: syslogTargetCreateSchema, section: "system" },
  async ({ auth, body }) => {
    const created = await createSyslogTarget(auth.tenantId, body);
    return {
      data: created,
      audit: { action: "syslog_target.create", objectType: "syslog_target", objectId: created.id, objectName: created.name, after: created },
    };
  },
);
