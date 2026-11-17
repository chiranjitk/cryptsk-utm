/**
 * IoT inventory stats (Phase 3 §3.6) — totals for the view chips: count by
 * deviceType, quarantined endpoints, average risk score and rogue candidates
 * (MAC unseen in DHCP leases, firstSeen <24h, unclassified).
 */

import { route } from "@/lib/api/handler";
import { getIotStats } from "@/lib/iot/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "identity" }, async ({ auth }) => {
  return { data: await getIotStats(auth.tenantId) };
});
