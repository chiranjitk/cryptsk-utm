/**
 * Restore a quarantined NAC device (M23, spec 2.9) — delegates to the shared
 * restoreNacDevice lifecycle in _lib/server.ts (also reused by the IoT
 * service): nacState → "authenticated", clears the quarantine VLAN, persists
 * an IdentityActivityEvent (`vlan_change`, { quarantined: false }) and audits
 * `nac.device.restore`.
 *
 * Guard area `nac` (audit fix #11 — was `identity`; nac.write includes
 * network_admin, per the RBAC matrix intent).
 */

import { route, numericId } from "@/lib/api/handler";
import { restoreNacDevice, toDeviceDTO } from "@/app/api/v1/identity-advanced/_lib/server";

export const dynamic = "force-dynamic";

export const POST = route({ area: "nac", section: "identity" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  const { device, audit } = await restoreNacDevice(auth.tenantId, id);
  return { data: toDeviceDTO(device, null), audit };
});
