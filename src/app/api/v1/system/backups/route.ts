/** GET/POST /api/v1/system/backups — list + create snapshots (M10 §5.3). */

import { route } from "@/lib/api/handler";
import { backupCreateSchema } from "@/lib/validators/system";
import { createBackup, listBackups } from "@/lib/system/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "backups" }, async ({ auth }) => {
  return { data: await listBackups(auth.tenantId) };
});

export const POST = route(
  { area: "backups", bodySchema: backupCreateSchema },
  async ({ auth, body }) => {
    const backup = await createBackup(auth.tenantId, body);
    return {
      data: backup,
      audit: {
        action: "backup.create",
        objectType: "backup",
        objectName: backup.id,
        after: backup,
      },
    };
  },
);
