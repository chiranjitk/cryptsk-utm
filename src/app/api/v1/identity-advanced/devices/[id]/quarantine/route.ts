/**
 * Quarantine a NAC device (M23, spec 2.9) — delegates to the shared
 * quarantineNacDevice lifecycle in _lib/server.ts (also reused by the IoT
 * service): nacState → "quarantine" with the optional VLAN, persists an
 * IdentityActivityEvent (`vlan_change`, { quarantined: true }) and audits
 * `nac.device.quarantine`.
 */

import { route, numericId } from "@/lib/api/handler";
import { quarantineSchema } from "@/lib/validators/identity-advanced";
import { quarantineNacDevice, toDeviceDTO } from "@/app/api/v1/identity-advanced/_lib/server";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "identity", bodySchema: quarantineSchema, section: "identity" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const { device, audit } = await quarantineNacDevice(auth.tenantId, id, body.vlanId);
    return { data: toDeviceDTO(device, null), audit };
  },
);
