/**
 * /api/v1/ztna/posture-profiles/[id] — update requirement set / rename and
 * delete (refused while access policies attach the profile).
 */

import { route, numericId } from "@/lib/api/handler";
import { postureProfileUpdateSchema } from "@/lib/validators/ztna";
import { deletePostureProfile, getPostureProfile, updatePostureProfile } from "@/lib/ztna/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "ztna" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  return { data: await getPostureProfile(auth.tenantId, id) };
});

export const PATCH = route(
  { area: "ztna", bodySchema: postureProfileUpdateSchema, section: "ztna" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const updated = await updatePostureProfile(auth.tenantId, id, body);
    return {
      data: updated,
      audit: {
        action: "ztna.posture-profile.update",
        objectType: "posture_profile",
        objectId: id,
        objectName: updated.name,
        after: updated,
      },
    };
  },
);

export const DELETE = route({ area: "ztna", section: "ztna" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  const deleted = await deletePostureProfile(auth.tenantId, id);
  return { data: deleted, audit: { action: "ztna.posture-profile.delete", objectType: "posture_profile", objectId: id } };
});
