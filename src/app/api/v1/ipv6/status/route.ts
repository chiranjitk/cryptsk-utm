/**
 * Computed dual-stack overview (M21 §2.7) — settings flags, the demo delegated
 * prefix, the v6/both firewall-rule count (filtering itself lives in the
 * EXISTING firewall-rules endpoints, M03 — not duplicated here) and NAT66 /
 * DHCPv6 counters.
 */

import { route } from "@/lib/api/handler";
import { getIpv6Status } from "@/app/api/v1/ipv6/shared";

export const dynamic = "force-dynamic";

export const GET = route({ area: "ipv6" }, async ({ auth }) => {
  return { data: await getIpv6Status(auth.tenantId) };
});
