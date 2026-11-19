/**
 * /api/v1/ztna/posture-profiles — device posture requirement sets (basic:
 * OS patch age, AV, disk encrypt, firewall — spec §4.4).
 */

import { route } from "@/lib/api/handler";
import { postureProfileCreateSchema } from "@/lib/validators/ztna";
import { createPostureProfile, listPostureProfiles } from "@/lib/ztna/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "ztna" }, async ({ auth }) => {
  return { data: await listPostureProfiles(auth.tenantId) };
});

export const POST = route(
  { area: "ztna", bodySchema: postureProfileCreateSchema, section: "ztna" },
  async ({ auth, body }) => {
    const created = await createPostureProfile(auth.tenantId, body);
    return {
      data: created,
      audit: {
        action: "ztna.posture-profile.create",
        objectType: "posture_profile",
        objectId: created.id,
        objectName: created.name,
        after: created,
      },
    };
  },
);
