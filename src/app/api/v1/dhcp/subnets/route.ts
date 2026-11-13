/** DHCP subnets (M06 §3) — list includes reservation/lease counts for the delete ConfirmDialog. */

import { route } from "@/lib/api/handler";
import { dhcpSubnetCreateSchema } from "@/lib/validators/dns-dhcp";
import { createSubnet, listSubnets } from "@/lib/dhcp/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "dns_dhcp" }, async ({ auth }) => {
  return { data: await listSubnets(auth.tenantId) };
});

export const POST = route(
  { area: "dns_dhcp", bodySchema: dhcpSubnetCreateSchema, section: "dhcp" },
  async ({ auth, body }) => {
    const created = await createSubnet(auth.tenantId, body);
    return {
      data: created,
      audit: { action: "dhcp_subnet.create", objectType: "dhcp_subnet", objectId: created.id, objectName: created.subnetCidr, after: created },
    };
  },
);
