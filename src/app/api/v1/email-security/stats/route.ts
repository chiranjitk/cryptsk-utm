/**
 * Mail log stats (M22 §2.8.6) — 24h delivered/quarantined/rejected counters,
 * average spam score (1dp), top 5 rejection/quarantine reasons and the
 * configured quarantine retention window.
 */

import { route } from "@/lib/api/handler";
import { getStats } from "@/app/api/v1/email-security/service";

export const dynamic = "force-dynamic";

export const GET = route({ area: "email_security" }, async ({ auth }) => {
  return { data: await getStats(auth.tenantId) };
});
