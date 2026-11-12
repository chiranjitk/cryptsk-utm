/** DHCP reservation item (M06 §3) — update / delete. */

import { route, numericId } from "@/lib/api/handler";
import { dhcpReservationUpdateSchema } from "@/lib/validators/dns-dhcp";
import { deleteReservation, updateReservation } from "@/lib/dhcp/service";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "dns_dhcp", bodySchema: dhcpReservationUpdateSchema, section: "dhcp" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const updated = await updateReservation(auth.tenantId, id, body);
    return {
      data: updated,
      audit: { action: "dhcp_reservation.update", objectType: "dhcp_reservation", objectId: id, objectName: updated.mac, after: updated },
    };
  },
);

export const DELETE = route({ area: "dns_dhcp", section: "dhcp" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  await deleteReservation(auth.tenantId, id);
  return { data: { ok: true }, audit: { action: "dhcp_reservation.delete", objectType: "dhcp_reservation", objectId: id } };
});
