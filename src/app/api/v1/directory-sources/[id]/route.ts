/**
 * Directory source item (M07 §3) — update (omit/masked `bindPassword` keeps
 * the stored value; there is NO reveal endpoint) / delete.
 */

import { route } from "@/lib/api/handler";
import { directorySourceUpdateSchema } from "@/lib/validators/identity";
import { deleteDirectorySource, updateDirectorySource } from "@/lib/identity/service";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "identity", bodySchema: directorySourceUpdateSchema, section: "identity" },
  async ({ auth, body, params }) => {
    const id = Number(params.id);
    const updated = await updateDirectorySource(auth.tenantId, id, body);
    return {
      data: updated,
      audit: { action: "directory_source.update", objectType: "directory_source", objectId: id, objectName: updated.name },
    };
  },
);

export const DELETE = route({ area: "identity", section: "identity" }, async ({ auth, params }) => {
  const id = Number(params.id);
  await deleteDirectorySource(auth.tenantId, id);
  return {
    data: { ok: true },
    audit: { action: "directory_source.delete", objectType: "directory_source", objectId: id },
  };
});
