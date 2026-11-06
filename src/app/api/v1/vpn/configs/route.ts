/**
 * /api/v1/vpn/configs — list + create (M05 §3). area: vpn_config.
 * Section `vpn` snapshots + `config:updated` broadcast on mutations.
 */

import { route } from "@/lib/api/handler";
import { vpnConfigCreateSchema } from "@/lib/validators/vpn";
import { createConfig, listConfigs } from "@/lib/vpn/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "vpn_config" }, async ({ auth }) => {
  return { data: await listConfigs(auth.tenantId) };
});

export const POST = route(
  { area: "vpn_config", bodySchema: vpnConfigCreateSchema, section: "vpn" },
  async ({ auth, body }) => {
    const created = await createConfig(auth.tenantId, body);
    return {
      data: created,
      audit: { action: "vpn_config.create", objectType: "vpn_config", objectId: created.id, objectName: created.name },
    };
  },
);
