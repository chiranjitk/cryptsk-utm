/**
 * GET /api/v1/ipv6/os-status — the GUI↔OS honesty view for the IPv6 module
 * (mirrors /api/v1/dns-dhcp/os-status + /api/v1/waf/os): real host facts for
 * kea-dhcp6 + radvd + nftables, per-entity drift (in-sync / drift / missing /
 * disabled / unsupported) computed against the RENDERED configs (hash +
 * normalized table block compare), sysctl forwarding, last apply state and
 * the full render preview (kea6 conf, radvd conf, nat66 nft file).
 */

import { route } from "@/lib/api/handler";
import { getIpv6OsStatus } from "@/lib/ipv6/os-service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "ipv6" }, async ({ auth }) => {
  return { data: await getIpv6OsStatus(auth.tenantId) };
});
