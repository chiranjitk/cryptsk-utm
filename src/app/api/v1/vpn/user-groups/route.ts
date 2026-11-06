/**
 * /api/v1/vpn/user-groups — list + create (M05 §3, REVIEW-4A restore).
 * Group pools must not overlap remote-access config pools or other groups (400).
 */

import { route } from "@/lib/api/handler";
import { vpnUserGroupCreateSchema } from "@/lib/validators/vpn";
import { createGroup, listGroups } from "@/lib/vpn/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "vpn_config" }, async ({ auth }) => {
  return { data: await listGroups(auth.tenantId) };
});

export const POST = route(
  { area: "vpn_config", bodySchema: vpnUserGroupCreateSchema, section: "vpn" },
  async ({ auth, body }) => {
    const created = await createGroup(auth.tenantId, body);
    return {
      data: created,
      audit: { action: "vpn_user_group.create", objectType: "vpn_user_group", objectId: created.id, objectName: created.name },
    };
  },
);
