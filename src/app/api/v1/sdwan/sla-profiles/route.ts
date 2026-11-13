/**
 * SLA profiles (M20 §2.5) — GET list + POST create.
 * Mutations audit `sla_profile.create` and snapshot section `sdwan`.
 */

import { route } from "@/lib/api/handler";
import { slaProfileCreateSchema } from "@/lib/validators/sdwan";
import { createSlaProfile, listSlaProfiles } from "@/app/api/v1/sdwan/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "sdwan" }, async ({ auth }) => {
  return { data: await listSlaProfiles(auth.tenantId) };
});

export const POST = route(
  { area: "sdwan", bodySchema: slaProfileCreateSchema, section: "sdwan" },
  async ({ auth, body }) => {
    const created = await createSlaProfile(auth.tenantId, body);
    return {
      data: created,
      audit: {
        action: "sla_profile.create",
        objectType: "sla_profile",
        objectId: created.id,
        objectName: created.name,
        after: created,
      },
    };
  },
);
