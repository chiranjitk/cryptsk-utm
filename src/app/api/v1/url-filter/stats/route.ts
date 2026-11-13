/**
 * URL filter stats (M16 §2.3.6) — 24h allowed/blocked/warned counters, top 5
 * blocked domains and a category breakdown over the same window.
 */

import { route } from "@/lib/api/handler";
import { getStats } from "@/app/api/v1/url-filter/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "url_filter" }, async ({ auth }) => {
  return { data: await getStats(auth.tenantId) };
});
