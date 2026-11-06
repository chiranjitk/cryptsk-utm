/**
 * User group item (M07 §3) — update incl. replace-all `memberIds` (service
 * diffs the membership rows in one tx) / delete (memberships cascade).
 */

import { route } from "@/lib/api/handler";
import { userGroupUpdateSchema } from "@/lib/validators/identity";
import { deleteGroup, updateGroup } from "@/lib/identity/service";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "identity", bodySchema: userGroupUpdateSchema, section: "identity" },
  async ({ auth, body, params }) => {
    const id = Number(params.id);
    const updated = await updateGroup(auth.tenantId, id, body);
    return {
      data: updated,
      audit: { action: "user_group.update", objectType: "user_group", objectId: id, objectName: updated.name, after: updated },
    };
  },
);

export const DELETE = route({ area: "identity", section: "identity" }, async ({ auth, params }) => {
  const id = Number(params.id);
  await deleteGroup(auth.tenantId, id);
  return {
    data: { ok: true },
    audit: { action: "user_group.delete", objectType: "user_group", objectId: id },
  };
});
