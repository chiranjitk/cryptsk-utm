/** DELETE /api/v1/system/ssh-keys/{id} — remove an SSH key (audited, M10 §5.7). */

import { route, numericId } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { deleteSshKey, listSshKeys } from "@/lib/system/service";

export const dynamic = "force-dynamic";

export const DELETE = route({ area: "system" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  if (!Number.isInteger(id)) throw ApiError.notFound("SSH key not found");
  const all = await listSshKeys(auth.tenantId);
  const key = all.find((k) => k.id === id);
  if (!key) throw ApiError.notFound("SSH key not found");
  await deleteSshKey(auth.tenantId, id);
  return {
    data: { ok: true },
    audit: {
      action: "ssh_key.delete",
      objectType: "ssh_key",
      objectId: id,
      objectName: key.name,
      before: { name: key.name, fingerprint: key.fingerprint },
    },
  };
});
