/** DHCP leases (M06 §3) — filtered list; no PATCH/DELETE (7-day history window). */

import { route } from "@/lib/api/handler";
import { dhcpLeaseQuerySchema } from "@/lib/validators/dns-dhcp";
import { listLeases } from "@/lib/dhcp/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "dns_dhcp", querySchema: dhcpLeaseQuerySchema }, async ({ auth, query }) => {
  const { data, meta } = await listLeases(auth.tenantId, query);
  return { data, meta };
});
