/** RADIUS profiles (M07 §3) — sharedSecret is ALWAYS masked in reads. */

import { route } from "@/lib/api/handler";
import { radiusProfileCreateSchema } from "@/lib/validators/identity";
import { createRadiusProfile, listRadiusProfiles } from "@/lib/identity/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "identity" }, async ({ auth }) => {
  return { data: await listRadiusProfiles(auth.tenantId) };
});

export const POST = route(
  { area: "identity", bodySchema: radiusProfileCreateSchema, section: "identity" },
  async ({ auth, body }) => {
    const created = await createRadiusProfile(auth.tenantId, body);
    return {
      data: created, // DTO carries the masked literal, never the secret
      audit: { action: "radius_profile.create", objectType: "radius_profile", objectId: created.id, objectName: created.name },
    };
  },
);
