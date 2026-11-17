/**
 * DLP incidents (Phase 3 §3.3) — GET server-paged list (status/severity/q
 * filters, ordered createdAt desc). Excerpts are engine-redacted (masked
 * spans) — the raw sensitive payload is never stored or returned.
 */

import { route } from "@/lib/api/handler";
import { dlpIncidentsQuerySchema } from "@/lib/validators/dlp";
import { listIncidents } from "@/lib/dlp/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "dlp", querySchema: dlpIncidentsQuerySchema }, async ({ auth, query }) => {
  const { data, meta } = await listIncidents(auth.tenantId, query);
  return { data, meta };
});
