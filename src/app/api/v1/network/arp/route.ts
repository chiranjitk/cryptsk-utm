/** GET /api/v1/network/arp — live ARP/neighbor cache from /proc/net/arp. */

import { route } from "@/lib/api/handler";
import { readArp } from "@/lib/host/diagnostics";

export const dynamic = "force-dynamic";

export const GET = route({ area: "network" }, async () => {
  const arp = await readArp();
  return { data: arp, meta: { page: 1, limit: arp.length, total: arp.length, totalPages: 1 } };
});
