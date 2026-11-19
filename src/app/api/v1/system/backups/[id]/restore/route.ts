/**
 * POST /api/v1/system/backups/{id}/restore — restore a snapshot (M10 §5.3).
 * Admin-class; auto-creates a safety backup first, audited as backup.restore,
 * and snapshots section "all" (sentinel → every view refetches).
 *
 * Destructive-action confirm token (F-e #1): the body MUST be
 * {"confirm": "<backupId>"} — a mismatch is rejected 400 BEFORE anything runs
 * (no safety backup, no row writes).
 */

import { route } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { restoreConfirmSchema } from "@/lib/validators/system";
import { restoreBackup } from "@/lib/system/service";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "backups", admin: true, bodySchema: restoreConfirmSchema, section: "all" },
  async ({ auth, body, params }) => {
    const id = params.id;
    if (body.confirm !== id) {
      throw ApiError.validation(`Confirm token mismatch — body must be {"confirm": "${id}"}`);
    }
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
