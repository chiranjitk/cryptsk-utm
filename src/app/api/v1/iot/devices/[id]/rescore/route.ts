/**
 * Re-score a single NAC device (Phase 3 §3.6) — recomputes the risk score
 * with the §3.6 formula (base 30, iot/camera +15, unknown +20, quarantined
 * +30, missing osGuess +10, clamped 0-100). Audits `iot.rescore`.
 */

import { route, numericId } from "@/lib/api/handler";
import { rescoreDevice } from "@/lib/iot/service";
import { toDeviceDTO } from "@/app/api/v1/identity-advanced/_lib/server";

export const dynamic = "force-dynamic";

export const POST = route({ area: "identity" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  const { device, audit } = await rescoreDevice(auth.tenantId, id);
  return { data: toDeviceDTO(device, null), audit };
});
