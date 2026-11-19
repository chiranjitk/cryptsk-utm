/**
 * /api/v1/soar/playbooks/[id]/run — manual fire (Phase 4 §4.6): executes the
 * chosen playbook synchronously for the given triggerRef/payload, bypassing
 * enabled/filter (operator override) but keeping dedupe + step semantics.
 */

import { route, numericId } from "@/lib/api/handler";
import { soarRunSchema } from "@/lib/validators/soar";
import { runPlaybookById } from "@/lib/soar/service";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "soar", bodySchema: soarRunSchema },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const run = await runPlaybookById(auth.tenantId, id, {
      triggerRef: body.triggerRef,
      payload: body.payload,
    });
    return {
      data: run,
      audit: {
        action: "soar.playbook.run",
        objectType: "soar_playbook",
        objectId: id,
        objectName: run.playbookName,
        after: { runId: run.id, status: run.status, triggerRef: run.triggerRef },
      },
    };
  },
);
