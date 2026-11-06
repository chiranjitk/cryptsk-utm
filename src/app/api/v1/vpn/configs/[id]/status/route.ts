/**
 * /api/v1/vpn/configs/[id]/status — tunnel state, DPD, handshakes (M05 §3).
 * Read-only engine view; the status dialog polls every 5 s while open.
 */

import { route } from "@/lib/api/handler";
import { statusDetail } from "@/lib/vpn/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "vpn_config" }, async ({ auth, params }) => {
  const id = Number(params.id);
  return { data: await statusDetail(auth.tenantId, id) };
});
