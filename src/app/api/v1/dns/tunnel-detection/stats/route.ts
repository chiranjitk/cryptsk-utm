/**
 * GET /api/v1/dns/tunnel-detection/stats — M06 console strip aggregates
 * (Phase 3 §3.4): open findings by verdict, totals and 7-day creation count
 * (prisma count / groupBy).
 */

import { route } from "@/lib/api/handler";
import { statsFindings } from "@/lib/dns/tunnel-service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "dns_dhcp" }, async ({ auth }) => {
  return { data: await statsFindings(auth.tenantId) };
});
