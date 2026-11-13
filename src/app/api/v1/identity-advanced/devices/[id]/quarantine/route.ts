/**
 * Quarantine a NAC device (M23, spec 2.9) — nacState → "quarantine" with the
 * optional VLAN (keeps the current one when omitted), persists an
 * IdentityActivityEvent (`vlan_change`, { quarantined: true }) and audits
 * `nac.device.quarantine`.
 */

import { route, numericId } from "@/lib/api/handler";
import { ApiError } from "@/lib/api/errors";
import { quarantineSchema } from "@/lib/validators/identity-advanced";
import { db } from "@/lib/db";
import { toDeviceDTO } from "@/app/api/v1/identity-advanced/_lib/server";

export const dynamic = "force-dynamic";

export const POST = route(
  { area: "identity", bodySchema: quarantineSchema, section: "identity" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const device = await db.nacDevice.findFirst({ where: { id, tenantId: auth.tenantId } });
    if (!device) throw ApiError.notFound("Device not found");

    const vlanId = body.vlanId ?? device.vlanId ?? null;
    const updated = await db.nacDevice.update({
      where: { id: device.id },
      data: { nacState: "quarantine", vlanId },
    });

    await db.identityActivityEvent.create({
      data: {
        tenantId: auth.tenantId,
        userName: device.hostname ?? device.macAddress,
        event: "vlan_change",
        detail: JSON.stringify({ quarantined: true, vlanId, mac: device.macAddress }),
      },
    });

    return {
      data: toDeviceDTO(updated, null),
      audit: {
        action: "nac.device.quarantine",
        objectType: "nac_device",
        objectId: device.id,
        objectName: device.hostname ?? device.macAddress,
        before: { nacState: device.nacState, vlanId: device.vlanId },
        after: { nacState: "quarantine", vlanId },
      },
    };
  },
);
