/** DHCPv6 server item (M21 §2.7) — update / delete, audit `dhcpv6.update|delete`. */

import { route, numericId } from "@/lib/api/handler";
import { dhcpv6UpdateSchema } from "@/lib/validators/ipv6";
import { deleteDhcpv6Server, updateDhcpv6Server } from "@/app/api/v1/ipv6/shared";

export const dynamic = "force-dynamic";

export const PUT = route(
  { area: "ipv6", bodySchema: dhcpv6UpdateSchema, section: "ipv6" },
  async ({ auth, body, params }) => {
    const id = numericId(params, "id");
    const updated = await updateDhcpv6Server(auth.tenantId, id, body);
    return {
      data: updated,
      audit: {
        action: "dhcpv6.update",
        objectType: "dhcpv6_server",
        objectId: id,
        objectName: updated.interfaceName,
        after: updated,
      },
    };
  },
);

export const DELETE = route({ area: "ipv6", section: "ipv6" }, async ({ auth, params }) => {
  const id = numericId(params, "id");
  await deleteDhcpv6Server(auth.tenantId, id);
  return { data: { ok: true }, audit: { action: "dhcpv6.delete", objectType: "dhcpv6_server", objectId: id } };
});
