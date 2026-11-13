/**
 * DHCPv6 servers (M21 §2.7) — GET list + POST create. interfaceName is unique
 * per tenant (P2002 → 409 via the handler); mutations audit `dhcpv6.create`
 * and snapshot section `ipv6`.
 */

import { route } from "@/lib/api/handler";
import { dhcpv6CreateSchema } from "@/lib/validators/ipv6";
import { createDhcpv6Server, listDhcpv6Servers } from "@/app/api/v1/ipv6/shared";

export const dynamic = "force-dynamic";

export const GET = route({ area: "ipv6" }, async ({ auth }) => {
  return { data: await listDhcpv6Servers(auth.tenantId) };
});

export const POST = route(
  { area: "ipv6", bodySchema: dhcpv6CreateSchema, section: "ipv6" },
  async ({ auth, body }) => {
    const created = await createDhcpv6Server(auth.tenantId, body);
    return {
      data: created,
      audit: {
        action: "dhcpv6.create",
        objectType: "dhcpv6_server",
        objectId: created.id,
        objectName: created.interfaceName,
        after: created,
      },
    };
  },
);
