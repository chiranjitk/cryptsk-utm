/**
 * /api/v1/vpn/configs/[id]/client-bundle — wg .conf / .ovpn download payload
 * (M05 §3/§5). Bundles exist only for WireGuard/OpenVPN; ipsec_* → 409.
 * WireGuard remote bundles append a provisioned peer to the config.
 */

import { route, numericId } from "@/lib/api/handler";
import { z } from "zod";
import { clientBundle } from "@/lib/vpn/service";

export const dynamic = "force-dynamic";

const bodySchema = z
  .object({
    peerName: z.string().max(64).optional(),
  })
  .optional();

export const POST = route(
  { area: "vpn_config", bodySchema, section: "vpn" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const bundle = await clientBundle(auth.tenantId, id, body?.peerName);
    return {
      data: bundle,
      audit: { action: "vpn_config.client_bundle", objectType: "vpn_config", objectId: id, objectName: bundle.filename },
    };
  },
);
