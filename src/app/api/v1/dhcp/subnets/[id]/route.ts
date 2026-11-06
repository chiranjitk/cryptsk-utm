/**
 * DHCP subnet item (M06 §3) — update / delete. Delete cascades reservations +
 * leases (SCHEMA onDelete: Cascade); the response reports the cascaded counts.
 */

import { route } from "@/lib/api/handler";
import { dhcpSubnetUpdateSchema } from "@/lib/validators/dns-dhcp";
import { deleteSubnet, updateSubnet } from "@/lib/dhcp/service";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "dns_dhcp", bodySchema: dhcpSubnetUpdateSchema, section: "dhcp" },
  async ({ auth, body, params }) => {
    const id = Number(params.id);
    const updated = await updateSubnet(auth.tenantId, id, body);
    return {
      data: updated,
      audit: { action: "dhcp_subnet.update", objectType: "dhcp_subnet", objectId: id, objectName: updated.subnetCidr, after: updated },
    };
  },
);

export const DELETE = route({ area: "dns_dhcp", section: "dhcp" }, async ({ auth, params }) => {
  const id = Number(params.id);
  const cascaded = await deleteSubnet(auth.tenantId, id);
  return {
    data: { ok: true, cascaded },
    audit: { action: "dhcp_subnet.delete", objectType: "dhcp_subnet", objectId: id, after: cascaded },
  };
});
