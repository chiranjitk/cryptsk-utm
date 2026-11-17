/**
 * Restore a quarantined NAC device (M23, spec 2.9) — delegates to the shared
 * restoreNacDevice lifecycle in _lib/server.ts (also reused by the IoT
 * service): nacState → "authenticated", clears the quarantine VLAN, persists
 * an IdentityActivityEvent (`vlan_change`, { quarantined: false }) and audits
 * `nac.device.restore`.
 */

import { route, numericId } from "@/lib/api/handler";
import { restoreNacDevice, toDeviceDTO } from "@/app/api/v1/identity-advanced/_lib/server";

export const dynamic = "force-dynamic";

export const POST = route({ area: "identity", section: "identity" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  const { device, audit } = await restoreNacDevice(auth.tenantId, id);
  return { data: toDeviceDTO(device, null), audit };
});
