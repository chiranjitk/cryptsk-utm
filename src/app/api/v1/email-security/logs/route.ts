/**
 * Mail log (M22 §2.8.5) — paged-lite list, newest first.
 * Filters: ?limit=100 (1–100), ?verdict=delivered|quarantined|rejected,
 * ?q= free text over fromAddr / toAddr / subject.
 */

import { route } from "@/lib/api/handler";
import { emailLogQuerySchema } from "@/lib/validators/email-security";
import { listLogs } from "@/app/api/v1/email-security/service";

export const dynamic = "force-dynamic";

export const GET = route(
  { area: "email_security", querySchema: emailLogQuerySchema },
  async ({ auth, query }) => {
    const { data, meta } = await listLogs(auth.tenantId, query);
    return { data, meta };
  },
);
