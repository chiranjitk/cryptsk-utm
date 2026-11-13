/** SD-WAN stats (M20 §2.5) — counts, paths-by-state, average + worst latency. */

import { route } from "@/lib/api/handler";
import { getStats } from "@/app/api/v1/sdwan/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "sdwan" }, async ({ auth }) => {
  return { data: await getStats(auth.tenantId) };
});
