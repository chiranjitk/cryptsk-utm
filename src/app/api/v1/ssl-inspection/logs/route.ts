/**
 * SSL inspection logs (M15 §2.1) — recent decisions, paged-lite
 * (?limit≤100&decision?&q?), newest first. Read-only.
 */

import { route } from "@/lib/api/handler";
import { sslLogQuerySchema } from "@/lib/validators/ssl-inspection";
import { listLogs } from "@/app/api/v1/ssl-inspection/shared";

export const dynamic = "force-dynamic";

export const GET = route({ area: "ssl_inspection", querySchema: sslLogQuerySchema }, async ({ auth, query }) => {
  return { data: await listLogs(auth.tenantId, query) };
});
