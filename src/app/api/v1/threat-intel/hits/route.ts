/**
 * GET /api/v1/threat-intel/hits?limit=50&since= — recent IOC matches
 * (M13 §2.11) joined with the IOC value/type/severity via explicit map
 * (logical ref). Ordered createdAt desc — powers the live "Recent matches"
 * panel (client refetches every 10s).
 */

import { route } from "@/lib/api/handler";
import { hitsQuerySchema } from "@/lib/validators/threat-intel";
import { listHits } from "@/lib/threat-intel/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "threat_intel", querySchema: hitsQuerySchema }, async ({ auth, query }) => {
  return { data: await listHits(auth.tenantId, query) };
});
