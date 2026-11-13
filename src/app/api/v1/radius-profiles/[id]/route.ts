/**
 * RADIUS profile item (M07 §3) — update (omit/masked `sharedSecret` keeps the
 * stored value) / delete. No read ever returns the clear secret.
 */

import { route, numericId } from "@/lib/api/handler";
import { radiusProfileUpdateSchema } from "@/lib/validators/identity";
import { deleteRadiusProfile, updateRadiusProfile } from "@/lib/identity/service";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "identity", bodySchema: radiusProfileUpdateSchema, section: "identity" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const updated = await updateRadiusProfile(auth.tenantId, id, body);
    return {
      data: updated,
      audit: { action: "radius_profile.update", objectType: "radius_profile", objectId: id, objectName: updated.name },
    };
  },
);

export const DELETE = route({ area: "identity", section: "identity" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  await deleteRadiusProfile(auth.tenantId, id);
  return {
    data: { ok: true },
    audit: { action: "radius_profile.delete", objectType: "radius_profile", objectId: id },
  };
});
