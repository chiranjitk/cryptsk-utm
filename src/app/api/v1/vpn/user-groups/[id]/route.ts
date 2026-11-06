/**
 * /api/v1/vpn/user-groups/[id] — update (incl. memberUsernames replace-all)
 * and delete (M05 §3). Members are logical refs to VpnSession.userName.
 */

import { route } from "@/lib/api/handler";
import { vpnUserGroupUpdateSchema } from "@/lib/validators/vpn";
import { deleteGroup, updateGroup } from "@/lib/vpn/service";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "vpn_config", bodySchema: vpnUserGroupUpdateSchema, section: "vpn" },
  async ({ auth, body, params }) => {
    const id = Number(params.id);
    const updated = await updateGroup(auth.tenantId, id, body);
    return {
      data: updated,
      audit: { action: "vpn_user_group.update", objectType: "vpn_user_group", objectId: id, objectName: updated.name },
    };
  },
);

export const DELETE = route({ area: "vpn_config", section: "vpn" }, async ({ auth, params }) => {
  const id = Number(params.id);
  await deleteGroup(auth.tenantId, id);
  return {
    data: { ok: true },
    audit: { action: "vpn_user_group.delete", objectType: "vpn_user_group", objectId: id },
  };
});
