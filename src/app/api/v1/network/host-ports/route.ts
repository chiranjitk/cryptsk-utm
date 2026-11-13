/**
 * GET /api/v1/network/host-ports — every physical interface the kernel sees,
 * merged with /proc/net/dev counters (rx/tx errors + drops). Vendor-parity
 * "host ports" inventory for the Diagnostics section.
 */

import { route } from "@/lib/api/handler";
import { readInterfaces } from "@/lib/host/proc";
import { readNetDev } from "@/lib/host/diagnostics";

export const dynamic = "force-dynamic";

export const GET = route({ area: "network" }, async () => {
  const [ifaces, counters] = await Promise.all([readInterfaces(), readNetDev()]);
  const byName = new Map(counters.map((c) => [c.name, c]));
  const data = ifaces.map((i) => ({
    ...i,
    counters: byName.get(i.name) ?? null,
  }));
  return { data, meta: { page: 1, limit: data.length, total: data.length, totalPages: 1 } };
});
