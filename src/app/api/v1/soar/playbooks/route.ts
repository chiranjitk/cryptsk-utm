/**
 * /api/v1/soar/playbooks — playbook list + creation (Phase 4 §4.6).
 * RBAC uses the dedicated "soar" capability area (mirrors the incidents
 * route pattern; area matrix lives in lib/auth/rbac.ts).
 */

import { route } from "@/lib/api/handler";
import { soarPlaybookCreateSchema } from "@/lib/validators/soar";
import { createPlaybook, listPlaybooks } from "@/lib/soar/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "soar" }, async ({ auth }) => {
  return listPlaybooks(auth.tenantId);
});

export const POST = route(
  { area: "soar", bodySchema: soarPlaybookCreateSchema },
  async ({ auth, body }) => {
    const created = await createPlaybook(auth.tenantId, body);
    return {
      data: created,
      audit: {
        action: "soar.playbook.create",
        objectType: "soar_playbook",
        objectId: created.id,
        objectName: created.name,
        after: created,
      },
    };
  },
);
