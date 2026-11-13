/** DHCP MAC reservations (M06 §3) — MAC unique per tenant (409 with holder). */

import { route } from "@/lib/api/handler";
import { dhcpReservationCreateSchema, dhcpReservationQuerySchema } from "@/lib/validators/dns-dhcp";
import { createReservation, listReservations } from "@/lib/dhcp/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "dns_dhcp", querySchema: dhcpReservationQuerySchema }, async ({ auth, query }) => {
  return { data: await listReservations(auth.tenantId, query.subnetId) };
});

export const POST = route(
  { area: "dns_dhcp", bodySchema: dhcpReservationCreateSchema, section: "dhcp" },
  async ({ auth, body }) => {
    const created = await createReservation(auth.tenantId, body);
    return {
      data: created,
      audit: { action: "dhcp_reservation.create", objectType: "dhcp_reservation", objectId: created.id, objectName: created.mac, after: created },
    };
  },
);
