/**
 * Restore a quarantined NAC device (M23, spec 2.9) — nacState →
 * "authenticated", clears the quarantine VLAN, persists an
 * IdentityActivityEvent (`vlan_change`, { quarantined: false }) and audits
 * `nac.device.restore`.
 */

import { route, numericId } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { db } from "@/lib/db";
import { toDeviceDTO } from "@/app/api/v1/identity-advanced/_lib/server";

export const dynamic = "force-dynamic";

export const POST = route({ area: "identity", section: "identity" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  const device = await db.nacDevice.findFirst({ where: { id, tenantId: auth.tenantId } });
  if (!device) throw ApiError.notFound("Device not found");

  const updated = await db.nacDevice.update({
    where: { id: device.id },
    data: { nacState: "authenticated", vlanId: null },
  });

  await db.identityActivityEvent.create({
    data: {
      tenantId: auth.tenantId,
      userName: device.hostname ?? device.macAddress,
      event: "vlan_change",
      detail: JSON.stringify({ quarantined: false, mac: device.macAddress }),
    },
  });

  return {
    data: toDeviceDTO(updated, null),
    audit: {
      action: "nac.device.restore",
      objectType: "nac_device",
      objectId: device.id,
      objectName: device.hostname ?? device.macAddress,
      before: { nacState: device.nacState, vlanId: device.vlanId },
      after: { nacState: "authenticated", vlanId: null },
    },
  };
});
