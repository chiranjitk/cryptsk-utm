/**
 * NetFlow/IPFIX forwarding targets (M09 §3) — GET list + POST create.
 * Mutations audit `netflow_target.create` and snapshot section `system`.
 */

import { route } from "@/lib/api/handler";
import { netflowTargetCreateSchema } from "@/lib/validators/logs";
import { createNetflowTarget, listNetflowTargets } from "@/lib/logs/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "log_forwarding" }, async ({ auth }) => {
  return { data: await listNetflowTargets(auth.tenantId) };
});

export const POST = route(
  { area: "log_forwarding", bodySchema: netflowTargetCreateSchema, section: "system" },
  async ({ auth, body }) => {
    const created = await createNetflowTarget(auth.tenantId, body);
    return {
      data: created,
      audit: { action: "netflow_target.create", objectType: "netflow_target", objectId: created.id, objectName: created.name, after: created },
    };
  },
);
