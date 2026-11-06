/** GET/POST /api/v1/system/ssh-keys — SSH management keys (M10 §5.7). */

import { route } from "@/lib/api/handler";
import { sshKeyCreateSchema } from "@/lib/validators/system";
import { createSshKey, listSshKeys } from "@/lib/system/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "system" }, async ({ auth }) => {
  return { data: await listSshKeys(auth.tenantId) };
});

export const POST = route(
  { area: "system", bodySchema: sshKeyCreateSchema },
  async ({ auth, body }) => {
    const key = await createSshKey(auth.tenantId, body, auth.username ?? "unknown");
    return {
      data: key,
      audit: {
        action: "ssh_key.create",
        objectType: "ssh_key",
        objectId: key.id,
        objectName: key.name,
        after: { name: key.name, fingerprint: key.fingerprint },
      },
    };
  },
);
