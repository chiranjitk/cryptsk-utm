/**
 * SSL inspection stats (M15 §2.1) — 24h decision counters, reason breakdown
 * and certificates/CAs expiring within 45 days (signing material health).
 * Read-only.
 */

import { route } from "@/lib/api/handler";
import { getStats } from "@/app/api/v1/ssl-inspection/shared";

export const dynamic = "force-dynamic";

export const GET = route({ area: "ssl_inspection" }, async ({ auth }) => {
  return { data: await getStats(auth.tenantId) };
});
