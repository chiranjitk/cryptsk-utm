/**
 * POST /api/v1/system/backups/{id}/restore — restore a snapshot (M10 §5.3).
 * Admin-class; auto-creates a safety backup first, audited as backup.restore,
 * and snapshots section "all" (sentinel → every view refetches).
 */

import { route } from "@/lib/api/handler";
import { z } from "@/lib/api/handler";
import { restoreBackup } from "@/lib/system/service";

export const dynamic = "force-dynamic";

const emptyBody = z.object({}).strict();

export const POST = route(
  { area: "backups", admin: true, bodySchema: emptyBody, section: "all" },
  async ({ auth, params }) => {
    const id = params.id;
    const result = await restoreBackup(auth.tenantId, id);
    return {
      data: { ok: true, restored: id, ...result },
      audit: {
        action: "backup.restore",
        objectType: "backup",
        objectName: id,
        after: result,
      },
    };
  },
);
