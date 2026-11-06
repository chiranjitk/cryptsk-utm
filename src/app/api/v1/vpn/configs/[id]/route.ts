/**
 * /api/v1/vpn/configs/[id] — update + delete (M05 §3). status/statusMessage
 * are engine-owned and never written here (ENDPOINTS §7). Delete cascades
 * the config's sessions (ER_DIAGRAM §2).
 */

import { route } from "@/lib/api/handler";
import { vpnConfigUpdateSchema } from "@/lib/validators/vpn";
import { deleteConfig, updateConfig } from "@/lib/vpn/service";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "vpn_config", bodySchema: vpnConfigUpdateSchema, section: "vpn" },
  async ({ auth, body, params }) => {
    const id = Number(params.id);
    const updated = await updateConfig(auth.tenantId, id, body);
    return {
      data: updated,
      audit: { action: "vpn_config.update", objectType: "vpn_config", objectId: id, objectName: updated.name },
    };
  },
);

export const DELETE = route({ area: "vpn_config", section: "vpn" }, async ({ auth, params }) => {
  const id = Number(params.id);
  await deleteConfig(auth.tenantId, id);
  return {
    data: { ok: true },
    audit: { action: "vpn_config.delete", objectType: "vpn_config", objectId: id },
  };
});
